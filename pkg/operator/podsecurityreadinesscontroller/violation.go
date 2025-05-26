package podsecurityreadinesscontroller

import (
	"context"
	"fmt"
	"strings"

	securityv1 "github.com/openshift/api/security/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	applyconfiguration "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/klog/v2"
	psapi "k8s.io/pod-security-admission/api"
)

const (
	syncerControllerName = "pod-security-admission-label-synchronization-controller"
)

var (
	alertLabels = sets.New(psapi.WarnLevelLabel, psapi.AuditLevelLabel)
)

// isNamespaceViolating checks if a namespace is ready for Pod Security Admission enforcement.
// Return value is whether the namespace is violating, whether the violation is related to a user workload (such as a direcly created pod), and error
func (c *PodSecurityReadinessController) isNamespaceViolating(ctx context.Context, ns *corev1.Namespace) (bool, bool, error) {
	nsApplyConfig, err := applyconfiguration.ExtractNamespace(ns, syncerControllerName)
	if err != nil {
		return false, false, err
	}

	enforceLabel, err := determineEnforceLabelForNamespace(nsApplyConfig)
	if err != nil {
		return false, false, err
	}

	nsApply := applyconfiguration.Namespace(ns.Name).WithLabels(map[string]string{
		psapi.EnforceLevelLabel: enforceLabel,
	})

	_, err = c.kubeClient.CoreV1().
		Namespaces().
		Apply(ctx, nsApply, metav1.ApplyOptions{
			DryRun:       []string{metav1.DryRunAll},
			FieldManager: "pod-security-readiness-controller",
		})
	if err != nil {
		return false, false, err
	}

	// If there are warnings, the namespace is violating.
	if len(c.warningsHandler.PopAll()) > 0 {
		// Check if the violation is related to a user workload.
		userViolation, err := c.isUserViolation(ctx, ns, enforceLabel)
		if err != nil {
			return false, false, err
		}

		return true, userViolation, nil
	}

	return false, false, nil
}

func (c *PodSecurityReadinessController) isUserViolation(ctx context.Context, ns *corev1.Namespace, label string) (bool, error) {
	if !shouldCheckForUserSCC(ns) {
		return false, nil
	}

	// Parse the violating level
	var enforcementLevel psapi.Level
	switch strings.ToLower(label) {
	case "restricted":
		enforcementLevel = psapi.LevelRestricted
	case "baseline":
		enforcementLevel = psapi.LevelBaseline
	case "privileged":
		// If privileged is violating, something is seriously wrong
		// but testing against privileged level is pointless (everything passes)
		klog.V(2).InfoS("Namespace violating privileged level - skipping user check", 
			"namespace", ns.Name)
		return false, nil
	default:
		return false, fmt.Errorf("unknown level: %q", label)
	}

	// List all pods and filter for user-annotated ones
	allPods, err := c.kubeClient.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
	if err != nil {
		klog.V(2).ErrorS(err, "Failed to list pods in namespace", "namespace", ns.Name)
		return false, err
	}

	// Filter for user-annotated pods
	var userPods []corev1.Pod
	for _, pod := range allPods.Items {
		if pod.Annotations[securityv1.ValidatedSCCSubjectTypeAnnotation] == "user" {
			userPods = append(userPods, pod)
		}
	}

	if len(userPods) == 0 {
		return false, nil // No user pods = violation is from service accounts
	}

	// Test user pods against the violating level
	enforcementVersion := psapi.LatestVersion()
	for _, pod := range userPods {
		results := c.psaEvaluator.EvaluatePod(
			psapi.LevelVersion{Level: enforcementLevel, Version: enforcementVersion},
			&pod.ObjectMeta,
			&pod.Spec,
		)

		for _, result := range results {
			if !result.Allowed {
				klog.V(4).InfoS("User pod violates PSA level", 
					"namespace", ns.Name, "pod", pod.Name, "level", label)
				return true, nil // User pod violates the level
			}
		}
	}

	return false, nil // User pods all pass - violation is from service accounts
}

func shouldCheckForUserSCC(ns *corev1.Namespace) bool {
	// Only check user SCC violations in customer namespaces
	// (not run-level-zero, openshift, or disabled syncer namespaces)
	return !runLevelZeroNamespaces.Has(ns.Name) && 
		   !strings.HasPrefix(ns.Name, "openshift") && 
		   ns.Labels[labelSyncControlLabel] != "false"
}

func determineEnforceLabelForNamespace(ns *applyconfiguration.NamespaceApplyConfiguration) (string, error) {
	if _, ok := ns.Annotations[securityv1.MinimallySufficientPodSecurityStandard]; ok {
		// Pick the MinimallySufficientPodSecurityStandard if it exists
		return ns.Annotations[securityv1.MinimallySufficientPodSecurityStandard], nil
	}

	viableLabels := map[string]string{}

	for alertLabel := range alertLabels {
		if value, ok := ns.Labels[alertLabel]; ok {
			viableLabels[alertLabel] = value
		}
	}

	if len(viableLabels) == 0 {
		// If there are no labels/annotations managed by the syncer, we can't make a decision.
		return "", fmt.Errorf("unable to determine if the namespace is violating because no appropriate labels or annotations were found")
	}

	return pickStrictest(viableLabels), nil
}

func pickStrictest(viableLabels map[string]string) string {
	targetLevel := ""
	for label, value := range viableLabels {
		level, err := psapi.ParseLevel(value)
		if err != nil {
			klog.V(4).InfoS("invalid level", "label", label, "value", value)
			continue
		}

		if targetLevel == "" {
			targetLevel = value
			continue
		}

		if psapi.CompareLevels(psapi.Level(targetLevel), level) < 0 {
			targetLevel = value
		}
	}

	if targetLevel == "" {
		// Global Config will set it to "restricted", but shouldn't happen.
		return string(psapi.LevelRestricted)
	}

	return targetLevel
}
