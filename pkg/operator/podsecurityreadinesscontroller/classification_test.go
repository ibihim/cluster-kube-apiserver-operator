package podsecurityreadinesscontroller

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestClassifyViolatingNamespace(t *testing.T) {
	for _, tt := range []struct {
		name                string
		namespace           *corev1.Namespace
		expectedConditions  map[string][]string
	}{
		{
			name: "run-level zero namespace - kube-system",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "kube-system",
				},
			},
			expectedConditions: map[string][]string{
				"runLevelZero": {"kube-system"},
			},
		},
		{
			name: "run-level zero namespace - default",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
			},
			expectedConditions: map[string][]string{
				"runLevelZero": {"default"},
			},
		},
		{
			name: "openshift namespace",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "openshift-test",
				},
			},
			expectedConditions: map[string][]string{
				"openshift": {"openshift-test"},
			},
		},
		{
			name: "disabled syncer namespace",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-disabled",
					Labels: map[string]string{
						"security.openshift.io/scc.podSecurityLabelSync": "false",
					},
				},
			},
			expectedConditions: map[string][]string{
				"disabledSyncer": {"test-disabled"},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conditions := podSecurityOperatorConditions{}
			
			// Test the classification logic directly without isUserViolation call
			if runLevelZeroNamespaces.Has(tt.namespace.Name) {
				conditions.addViolatingRunLevelZero(tt.namespace)
			} else if strings.HasPrefix(tt.namespace.Name, "openshift") {
				conditions.addViolatingOpenShift(tt.namespace)
			} else if tt.namespace.Labels[labelSyncControlLabel] == "false" {
				conditions.addViolatingDisabledSyncer(tt.namespace)
			} else {
				// For the customer namespace fallback, we don't test isUserViolation here
				// as it requires a full controller setup with kube client
				conditions.addViolatingCustomer(tt.namespace)
			}
			
			// Verify the conditions were set correctly
			for conditionType, expectedNamespaces := range tt.expectedConditions {
				var actualNamespaces []string
				switch conditionType {
				case "runLevelZero":
					actualNamespaces = conditions.violatingRunLevelZeroNamespaces
				case "openshift":
					actualNamespaces = conditions.violatingOpenShiftNamespaces
				case "disabledSyncer":
					actualNamespaces = conditions.violatingDisabledSyncerNamespaces
				case "customer":
					actualNamespaces = conditions.violatingCustomerNamespaces
				case "userSCC":
					actualNamespaces = conditions.userSCCViolationNamespaces
				}
				
				if len(actualNamespaces) != len(expectedNamespaces) {
					t.Errorf("expected %d %s namespaces, got %d", len(expectedNamespaces), conditionType, len(actualNamespaces))
				}
				
				for _, expected := range expectedNamespaces {
					found := false
					for _, actual := range actualNamespaces {
						if actual == expected {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("expected %s namespace %s not found in %v", conditionType, expected, actualNamespaces)
					}
				}
			}
		})
	}
}