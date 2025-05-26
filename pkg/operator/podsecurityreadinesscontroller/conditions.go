package podsecurityreadinesscontroller

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	PodSecurityCustomerType       = "PodSecurityCustomerEvaluationConditionsDetected"
	PodSecurityOpenshiftType      = "PodSecurityOpenshiftEvaluationConditionsDetected"
	PodSecurityRunLevelZeroType   = "PodSecurityRunLevelZeroEvaluationConditionsDetected"
	PodSecurityDisabledSyncerType = "PodSecurityDisabledSyncerEvaluationConditionsDetected"
	PodSecurityInconclusiveType   = "PodSecurityInconclusiveEvaluationConditionsDetected"
	PodSecurityUserSCCType        = "PodSecurityUserSCCViolationConditionsDetected"

	labelSyncControlLabel = "security.openshift.io/scc.podSecurityLabelSync"

	violationReason    = "PSViolationsDetected"
	inconclusiveReason = "PSViolationDecisionInconclusive"
)

var (
	// run-level zero namespaces, shouldn't avoid openshift namespaces
	runLevelZeroNamespaces = sets.New[string](
		"default",
		"kube-system",
		"kube-public",
	)
)

type podSecurityOperatorConditions struct {
	violatingOpenShiftNamespaces      []string
	violatingRunLevelZeroNamespaces   []string
	violatingCustomerNamespaces       []string
	violatingDisabledSyncerNamespaces []string
	inconclusiveNamespaces            []string
	userSCCViolationNamespaces        []string
}

func (c *podSecurityOperatorConditions) addViolation(ns *corev1.Namespace, isUserViolation bool) {
	// Consolidated namespace categorization logic
	if runLevelZeroNamespaces.Has(ns.Name) {
		c.violatingRunLevelZeroNamespaces = append(c.violatingRunLevelZeroNamespaces, ns.Name)
		return
	}

	isOpenShift := strings.HasPrefix(ns.Name, "openshift")
	if isOpenShift {
		c.violatingOpenShiftNamespaces = append(c.violatingOpenShiftNamespaces, ns.Name)
		return
	}

	if ns.Labels[labelSyncControlLabel] == "false" {
		c.violatingDisabledSyncerNamespaces = append(c.violatingDisabledSyncerNamespaces, ns.Name)
		return
	}

	// For customer namespaces, track both general and user-specific violations
	c.violatingCustomerNamespaces = append(c.violatingCustomerNamespaces, ns.Name)
	if isUserViolation {
		c.userSCCViolationNamespaces = append(c.userSCCViolationNamespaces, ns.Name)
	}
}

func (c *podSecurityOperatorConditions) addInconclusive(ns *corev1.Namespace) {
	c.inconclusiveNamespaces = append(c.inconclusiveNamespaces, ns.Name)
}

func makeCondition(conditionType, conditionReason string, namespaces []string) operatorv1.OperatorCondition {
	var messageFormatter string

	switch conditionReason {
	case violationReason:
		messageFormatter = "Violations detected in namespaces: %v"
	case inconclusiveReason:
		messageFormatter = "Could not evaluate violations for namespaces: %v"
	default:
		messageFormatter = "Unexpected condition for namespace: %v"
	}

	if len(namespaces) > 0 {
		sort.Strings(namespaces)
		return operatorv1.OperatorCondition{
			Type:               conditionType,
			Status:             operatorv1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             conditionReason,
			Message: fmt.Sprintf(
				messageFormatter,
				namespaces,
			),
		}
	}

	return operatorv1.OperatorCondition{
		Type:               conditionType,
		Status:             operatorv1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             "ExpectedReason",
	}
}

func (c *podSecurityOperatorConditions) toConditionFuncs() []v1helpers.UpdateStatusFunc {
	return []v1helpers.UpdateStatusFunc{
		v1helpers.UpdateConditionFn(makeCondition(PodSecurityCustomerType, violationReason, c.violatingCustomerNamespaces)),
		v1helpers.UpdateConditionFn(makeCondition(PodSecurityOpenshiftType, violationReason, c.violatingOpenShiftNamespaces)),
		v1helpers.UpdateConditionFn(makeCondition(PodSecurityRunLevelZeroType, violationReason, c.violatingRunLevelZeroNamespaces)),
		v1helpers.UpdateConditionFn(makeCondition(PodSecurityDisabledSyncerType, violationReason, c.violatingDisabledSyncerNamespaces)),
		v1helpers.UpdateConditionFn(makeCondition(PodSecurityInconclusiveType, inconclusiveReason, c.inconclusiveNamespaces)),
		v1helpers.UpdateConditionFn(makeCondition(PodSecurityUserSCCType, violationReason, c.userSCCViolationNamespaces)),
	}
}
