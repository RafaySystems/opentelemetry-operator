package manager

import (
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	routev1 "github.com/openshift/api/route/v1"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	otelv1alpha1 "github.com/open-telemetry/opentelemetry-operator/apis/v1alpha1"
	otelv1beta1 "github.com/open-telemetry/opentelemetry-operator/apis/v1beta1"
	"github.com/open-telemetry/opentelemetry-operator/internal/autodetect"
	"github.com/open-telemetry/opentelemetry-operator/internal/autodetect/certmanager"
	"github.com/open-telemetry/opentelemetry-operator/internal/autodetect/collector"
	"github.com/open-telemetry/opentelemetry-operator/internal/autodetect/opampbridge"
	"github.com/open-telemetry/opentelemetry-operator/internal/autodetect/openshift"
	"github.com/open-telemetry/opentelemetry-operator/internal/autodetect/prometheus"
	"github.com/open-telemetry/opentelemetry-operator/internal/autodetect/targetallocator"
	"github.com/open-telemetry/opentelemetry-operator/internal/config"
	"github.com/open-telemetry/opentelemetry-operator/internal/controllers"
	"github.com/open-telemetry/opentelemetry-operator/internal/fips"
	"github.com/open-telemetry/opentelemetry-operator/internal/instrumentation"
	instrumentationupgrade "github.com/open-telemetry/opentelemetry-operator/internal/instrumentation/upgrade"
	collectorManifests "github.com/open-telemetry/opentelemetry-operator/internal/manifests/collector"
	openshiftDashboards "github.com/open-telemetry/opentelemetry-operator/internal/openshift/dashboards"
	operatormetrics "github.com/open-telemetry/opentelemetry-operator/internal/operator-metrics"
	"github.com/open-telemetry/opentelemetry-operator/internal/operatornetworkpolicy"
	"github.com/open-telemetry/opentelemetry-operator/internal/rbac"
	"github.com/open-telemetry/opentelemetry-operator/internal/version"
	"github.com/open-telemetry/opentelemetry-operator/internal/webhook/podmutation"
	"github.com/open-telemetry/opentelemetry-operator/pkg/featuregate"
	"github.com/open-telemetry/opentelemetry-operator/pkg/sidecar"
)

// Options controls how the OpenTelemetry Operator is embedded into an existing controller-runtime manager.
//
// This package intentionally does not expose the operator's internal config types. Configuration is loaded the same
// way as in the standalone operator binary: defaults + config file (optional) + env vars + CLI flags.
type Options struct {
	// ConfigFile is the path to a YAML config file (same format as the standalone operator).
	ConfigFile string

	// Clientset is optional. When nil, a clientset is created from mgr.GetConfig().
	Clientset kubernetes.Interface

	// EnableWebhooks controls whether the operator registers its webhooks onto mgr's webhook server.
	// If nil, the value is taken from the operator configuration (defaults to true).
	EnableWebhooks *bool
}

// AddToManager registers the OpenTelemetry Operator controllers/webhooks/runnables into an existing manager.
//
// This is the primary entrypoint for embedding the operator into another operator/binary.
func AddToManager(mgr ctrl.Manager) error {
	return AddToManagerWithOptions(mgr, Options{})
}

// AddToManagerWithOptions is the configurable variant of AddToManager.
func AddToManagerWithOptions(mgr ctrl.Manager, opts Options) error {
	if mgr == nil {
		return fmt.Errorf("manager must not be nil")
	}

	// Base schemes required for the operator's APIs.
	if err := ensureBaseSchemes(mgr.GetScheme()); err != nil {
		return err
	}

	cfg := config.New()
	if err := cfg.Apply(opts.ConfigFile); err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}
	if opts.EnableWebhooks != nil {
		cfg.EnableWebhooks = *opts.EnableWebhooks
	}

	// Validate filter regexes early (matches main.go behavior, but returns error instead of only logging).
	if err := validateRegexList(cfg.AnnotationsFilter); err != nil {
		return fmt.Errorf("invalid annotations filter: %w", err)
	}
	if err := validateRegexList(cfg.LabelsFilter); err != nil {
		return fmt.Errorf("invalid labels filter: %w", err)
	}

	clientset := opts.Clientset
	if clientset == nil {
		cs, err := kubernetes.NewForConfig(mgr.GetConfig())
		if err != nil {
			return fmt.Errorf("failed to create kubernetes clientset: %w", err)
		}
		clientset = cs
	}

	reviewer := rbac.NewReviewer(clientset)

	ad, err := autodetect.New(mgr.GetConfig(), reviewer)
	if err != nil {
		return fmt.Errorf("failed to setup auto-detect routine: %w", err)
	}

	if err := autodetect.ApplyAutoDetect(ad, &cfg, ctrl.Log.WithName("config")); err != nil {
		return fmt.Errorf("failed to autodetect config variables: %w", err)
	}

	// Conditional schemes (mirrors main.go).
	if err := ensureOptionalSchemes(mgr.GetScheme(), cfg); err != nil {
		return err
	}

	// Enforce collector CRD presence unless explicitly ignored (mirrors main.go, but returns error).
	if cfg.CollectorAvailability != collector.Available && !cfg.IgnoreMissingCollectorCRDs {
		return fmt.Errorf("missing OpenTelemetryCollector CRDs: set ignore_missing_collector_crds to true or install the CRDs")
	}

	// Add upgrade runnable (mirrors main.go:addDependencies).
	if err := mgr.Add(manager.RunnableFunc(func(c context.Context) error {
		u := instrumentationupgrade.NewInstrumentationUpgrade(
			mgr.GetClient(),
			ctrl.Log.WithName("instrumentation-upgrade"),
			mgr.GetEventRecorderFor("opentelemetry-operator"),
			cfg,
		)
		return u.ManagedInstances(c)
	})); err != nil {
		return fmt.Errorf("failed to add Instrumentation upgrade runnable: %w", err)
	}

	v := version.Get()

	// Controllers (mirrors main.go).
	var collectorReconciler *controllers.OpenTelemetryCollectorReconciler
	if cfg.CollectorAvailability == collector.Available {
		collectorReconciler = controllers.NewReconciler(controllers.Params{
			Client:   mgr.GetClient(),
			Log:      ctrl.Log.WithName("controllers").WithName("OpenTelemetryCollector"),
			Scheme:   mgr.GetScheme(),
			Config:   cfg,
			Recorder: mgr.GetEventRecorderFor("opentelemetry-operator"),
			Reviewer: reviewer,
			Version:  v,
		})
		if err := collectorReconciler.SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to create controller OpenTelemetryCollector: %w", err)
		}
	}

	if cfg.TargetAllocatorAvailability == targetallocator.Available {
		if err := controllers.NewTargetAllocatorReconciler(
			mgr.GetClient(),
			mgr.GetScheme(),
			mgr.GetEventRecorderFor("targetallocator"),
			cfg,
			ctrl.Log.WithName("controllers").WithName("TargetAllocator"),
		).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to create controller TargetAllocator: %w", err)
		}
	}

	if cfg.OpAmpBridgeAvailability == opampbridge.Available {
		if err := controllers.NewOpAMPBridgeReconciler(controllers.OpAMPBridgeReconcilerParams{
			Client:   mgr.GetClient(),
			Log:      ctrl.Log.WithName("controllers").WithName("OpAMPBridge"),
			Scheme:   mgr.GetScheme(),
			Config:   cfg,
			Recorder: mgr.GetEventRecorderFor("opamp-bridge"),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to create controller OpAMPBridge: %w", err)
		}
	}

	// Optional OpenShift dashboard management.
	if cfg.OpenshiftCreateDashboard {
		if err := mgr.Add(openshiftDashboards.NewDashboardManagement(clientset)); err != nil {
			return fmt.Errorf("failed to create the OpenShift dashboards: %w", err)
		}
	}

	// Optional operator network policy.
	if featuregate.EnableOperatorNetworkPolicy.IsEnabled() {
		if err := addOperatorNetworkPolicy(mgr, clientset, cfg); err != nil {
			return err
		}
	}

	// Optional operator metrics ServiceMonitor.
	if cfg.PrometheusCRAvailability == prometheus.Available && cfg.CreateServiceMonitorOperatorMetrics {
		operatorMetrics, err := operatormetrics.NewOperatorMetrics(mgr.GetConfig(), mgr.GetScheme(), ctrl.Log.WithName("operator-metrics-sm"))
		if err != nil {
			return fmt.Errorf("failed to create the operator metrics ServiceMonitor runnable: %w", err)
		}
		if err := mgr.Add(operatorMetrics); err != nil {
			return fmt.Errorf("failed to add the operator metrics ServiceMonitor runnable: %w", err)
		}
	}

	// Webhooks (mirrors main.go).
	if cfg.EnableWebhooks {
		var crdMetrics *otelv1beta1.Metrics
		if cfg.EnableCRMetrics {
			meterProvider, metricsErr := otelv1beta1.BootstrapMetrics()
			if metricsErr != nil {
				return fmt.Errorf("error bootstrapping CRD metrics: %w", metricsErr)
			}
			crdMetrics, err = otelv1beta1.NewMetrics(meterProvider, context.Background(), mgr.GetAPIReader())
			if err != nil {
				return fmt.Errorf("error initializing CRD metrics: %w", err)
			}
		}

		if cfg.CollectorAvailability == collector.Available && collectorReconciler != nil {
			bv := func(ctx context.Context, c otelv1beta1.OpenTelemetryCollector) admission.Warnings {
				var warnings admission.Warnings
				params, paramsErr := collectorReconciler.GetParams(ctx, c)
				if paramsErr != nil {
					return append(warnings, paramsErr.Error())
				}
				params.ErrorAsWarning = true
				if _, buildErr := collectorManifests.Build(params); buildErr != nil {
					return append(warnings, buildErr.Error())
				}
				return warnings
			}

			var fipsCheck fips.FIPSCheck
			if ad.FIPSEnabled(context.Background()) {
				receivers, exporters, processors, extensions := parseFipsFlag(cfg.FipsDisabledComponents)
				fipsCheck = fips.NewFipsCheck(receivers, exporters, processors, extensions)
			}

			if err := otelv1beta1.SetupCollectorWebhook(mgr, cfg, reviewer, crdMetrics, bv, fipsCheck); err != nil {
				return fmt.Errorf("unable to create webhook OpenTelemetryCollector: %w", err)
			}
		}

		if cfg.TargetAllocatorAvailability == targetallocator.Available {
			if err := otelv1alpha1.SetupTargetAllocatorWebhook(mgr, cfg, reviewer); err != nil {
				return fmt.Errorf("unable to create webhook TargetAllocator: %w", err)
			}
		}

		if err := otelv1alpha1.SetupInstrumentationWebhook(mgr, cfg); err != nil {
			return fmt.Errorf("unable to create webhook Instrumentation: %w", err)
		}

		// Pod mutation webhook path used by the standalone operator.
		decoder := admission.NewDecoder(mgr.GetScheme())
		mgr.GetWebhookServer().Register("/mutate-v1-pod", &webhook.Admission{
			Handler: podmutation.NewWebhookHandler(cfg, ctrl.Log.WithName("pod-webhook"), decoder, mgr.GetClient(),
				[]podmutation.PodMutator{
					sidecar.NewMutator(ctrl.Log, cfg, mgr.GetClient()),
					instrumentation.NewMutator(ctrl.Log, mgr.GetClient(), mgr.GetEventRecorderFor("opentelemetry-operator"), cfg),
				}),
		})

		if cfg.OpAmpBridgeAvailability == opampbridge.Available {
			if err := otelv1alpha1.SetupOpAMPBridgeWebhook(mgr, cfg); err != nil {
				return fmt.Errorf("unable to create webhook OpAMPBridge: %w", err)
			}
		}
	}

	return nil
}

func ensureBaseSchemes(s *k8sruntime.Scheme) error {
	if s == nil {
		return fmt.Errorf("scheme must not be nil")
	}
	if err := clientgoscheme.AddToScheme(s); err != nil {
		return err
	}
	if err := otelv1alpha1.AddToScheme(s); err != nil {
		return err
	}
	if err := otelv1beta1.AddToScheme(s); err != nil {
		return err
	}
	if err := networkingv1.AddToScheme(s); err != nil {
		return err
	}
	return nil
}

func ensureOptionalSchemes(s *k8sruntime.Scheme, cfg config.Config) error {
	if cfg.PrometheusCRAvailability == prometheus.Available {
		if err := monitoringv1.AddToScheme(s); err != nil {
			return fmt.Errorf("failed adding prometheus scheme: %w", err)
		}
	}
	if cfg.OpenShiftRoutesAvailability == openshift.RoutesAvailable {
		if err := routev1.Install(s); err != nil {
			return fmt.Errorf("failed adding openshift routes scheme: %w", err)
		}
	}
	if cfg.CertManagerAvailability == certmanager.Available {
		if err := cmv1.AddToScheme(s); err != nil {
			return fmt.Errorf("failed adding cert-manager scheme: %w", err)
		}
	}
	return nil
}

func validateRegexList(patterns []string) error {
	for _, p := range patterns {
		if p == "" {
			continue
		}
		if _, err := regexp.Compile(p); err != nil {
			return err
		}
	}
	return nil
}

func addOperatorNetworkPolicy(mgr ctrl.Manager, clientset kubernetes.Interface, cfg config.Config) error {
	operatorNamespace := os.Getenv("NAMESPACE")
	if operatorNamespace == "" {
		return fmt.Errorf("NAMESPACE environment variable is not set; required for the Operator Network Policy to work")
	}

	var policyOpts []operatornetworkpolicy.Option
	policyOpts = append(policyOpts, operatornetworkpolicy.WithOperatorNamespace(operatorNamespace))

	if cfg.OpenShiftRoutesAvailability == openshift.RoutesAvailable {
		policyOpts = append(policyOpts, operatornetworkpolicy.WithAPISererPodLabelSelector(&metav1.LabelSelector{
			MatchLabels: map[string]string{"apiserver": "true"},
		}))
		policyOpts = append(policyOpts, operatornetworkpolicy.WithAPISererNamespaceLabelSelector(&metav1.LabelSelector{
			MatchLabels: map[string]string{"kubernetes.io/metadata.name": "openshift-kube-apiserver"},
		}))
	}

	if cfg.EnableWebhooks {
		//nolint:gosec // disable G115
		policyOpts = append(policyOpts, operatornetworkpolicy.WithWebhookPort(int32(cfg.WebhookPort)))
	}

	if cfg.MetricsAddr != "" {
		_, portStr, err := net.SplitHostPort(cfg.MetricsAddr)
		if err != nil {
			return fmt.Errorf("failed to parse port from metrics address: %w", err)
		}
		metricsPort, err := strconv.ParseInt(portStr, 10, 32)
		if err != nil {
			return fmt.Errorf("failed to parse port for the metrics address: %w", err)
		}
		policyOpts = append(policyOpts, operatornetworkpolicy.WithMetricsPort(int32(metricsPort)))
	}

	if err := mgr.Add(operatornetworkpolicy.NewOperatorNetworkPolicy(clientset, mgr.GetScheme(), policyOpts...)); err != nil {
		return fmt.Errorf("failed to create the Operator network policies: %w", err)
	}
	return nil
}

func parseFipsFlag(fipsFlag string) ([]string, []string, []string, []string) {
	split := strings.Split(fipsFlag, ",")
	var receivers []string
	var exporters []string
	var processors []string
	var extensions []string
	for _, val := range split {
		val = strings.TrimSpace(val)
		typeAndName := strings.Split(val, ".")
		if len(typeAndName) != 2 {
			continue
		}
		componentType := typeAndName[0]
		name := typeAndName[1]

		switch componentType {
		case "receiver":
			receivers = append(receivers, name)
		case "exporter":
			exporters = append(exporters, name)
		case "processor":
			processors = append(processors, name)
		case "extension":
			extensions = append(extensions, name)
		}
	}
	return receivers, exporters, processors, extensions
}
