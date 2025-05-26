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
// It returns true if the namespace is violating the Pod Security Admission policy, along with
// the enforce label it was tested against.
func (c *PodSecurityReadinessController) isNamespaceViolating(ctx context.Context, ns *corev1.Namespace) (bool, string, error) {
	nsApplyConfig, err := applyconfiguration.ExtractNamespace(ns, syncerControllerName)
	if err != nil {
		return false, "", err
	}

	enforceLabel := determineEnforceLabelForNamespace(nsApplyConfig)
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
		return false, "", err
	}

	// If there are warnings, the namespace is violating.
	warnings := c.warningsHandler.PopAll()
	if len(warnings) > 0 {
		return true, enforceLabel, nil
	}

	return false, "", nil
}

func determineEnforceLabelForNamespace(ns *applyconfiguration.NamespaceApplyConfiguration) string {
	if _, ok := ns.Annotations[securityv1.MinimallySufficientPodSecurityStandard]; ok {
		// Pick the MinimallySufficientPodSecurityStandard if it exists
		return ns.Annotations[securityv1.MinimallySufficientPodSecurityStandard]
	}

	targetLevel := ""
	for label := range alertLabels {
		value, ok := ns.Labels[label]
		if !ok {
			continue
		}

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

func (c *PodSecurityReadinessController) isUserViolation(ctx context.Context, ns *corev1.Namespace, label string) (bool, error) {
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
