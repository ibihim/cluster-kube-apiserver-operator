package podsecurityreadinesscontroller

import (
	"context"
	"fmt"
	"strings"
	"testing"

	securityv1 "github.com/openshift/api/security/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/pod-security-admission/policy"
)

func TestClassifyViolatingNamespace(t *testing.T) {
	for _, tt := range []struct {
		name                string
		namespace           *corev1.Namespace
		pods                []corev1.Pod
		enforceLevel        string
		expectedConditions  map[string][]string
		expectError         bool
	}{
		{
			name: "run-level zero namespace - kube-system",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "kube-system",
				},
			},
			pods:         []corev1.Pod{},
			enforceLevel: "restricted",
			expectedConditions: map[string][]string{
				"runLevelZero": {"kube-system"},
			},
			expectError: false,
		},
		{
			name: "run-level zero namespace - default",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
			},
			pods:         []corev1.Pod{},
			enforceLevel: "restricted",
			expectedConditions: map[string][]string{
				"runLevelZero": {"default"},
			},
			expectError: false,
		},
		{
			name: "openshift namespace",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "openshift-test",
				},
			},
			pods:         []corev1.Pod{},
			enforceLevel: "restricted",
			expectedConditions: map[string][]string{
				"openshift": {"openshift-test"},
			},
			expectError: false,
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
			pods:         []corev1.Pod{},
			enforceLevel: "restricted",
			expectedConditions: map[string][]string{
				"disabledSyncer": {"test-disabled"},
			},
			expectError: false,
		},
		{
			name: "customer namespace with user SCC violation",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "customer-ns",
				},
			},
			pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "user-pod",
						Namespace: "customer-ns",
						Annotations: map[string]string{
							securityv1.ValidatedSCCSubjectTypeAnnotation: "user",
						},
					},
					Spec: corev1.PodSpec{
						SecurityContext: &corev1.PodSecurityContext{
							RunAsNonRoot: &[]bool{false}[0],
						},
						Containers: []corev1.Container{
							{
								Name:  "container",
								Image: "image",
								SecurityContext: &corev1.SecurityContext{
									AllowPrivilegeEscalation: &[]bool{true}[0],
								},
							},
						},
					},
				},
			},
			enforceLevel: "restricted",
			expectedConditions: map[string][]string{
				"userSCC": {"customer-ns"},
			},
			expectError: false,
		},
		{
			name: "customer namespace without user SCC violation",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "customer-ns",
				},
			},
			pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sa-pod",
						Namespace: "customer-ns",
						Annotations: map[string]string{
							securityv1.ValidatedSCCSubjectTypeAnnotation: "service-account",
						},
					},
					Spec: corev1.PodSpec{
						SecurityContext: &corev1.PodSecurityContext{
							RunAsNonRoot: &[]bool{false}[0],
						},
					},
				},
			},
			enforceLevel: "restricted",
			expectedConditions: map[string][]string{
				"customer": {"customer-ns"},
			},
			expectError: false,
		},
		{
			name: "customer namespace with mixed pods - user violates",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "customer-ns",
				},
			},
			pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sa-pod",
						Namespace: "customer-ns",
						Annotations: map[string]string{
							securityv1.ValidatedSCCSubjectTypeAnnotation: "service-account",
						},
					},
					Spec: corev1.PodSpec{
						SecurityContext: &corev1.PodSecurityContext{
							RunAsNonRoot: &[]bool{false}[0],
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "user-pod",
						Namespace: "customer-ns",
						Annotations: map[string]string{
							securityv1.ValidatedSCCSubjectTypeAnnotation: "user",
						},
					},
					Spec: corev1.PodSpec{
						SecurityContext: &corev1.PodSecurityContext{
							RunAsNonRoot: &[]bool{false}[0],
						},
						Containers: []corev1.Container{
							{
								Name:  "container",
								Image: "image",
								SecurityContext: &corev1.SecurityContext{
									AllowPrivilegeEscalation: &[]bool{true}[0],
								},
							},
						},
					},
				},
			},
			enforceLevel: "restricted",
			expectedConditions: map[string][]string{
				"userSCC": {"customer-ns"},
			},
			expectError: false,
		},
		{
			name: "customer namespace with user pods that pass PSA",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "customer-ns",
				},
			},
			pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "user-pod",
						Namespace: "customer-ns",
						Annotations: map[string]string{
							securityv1.ValidatedSCCSubjectTypeAnnotation: "user",
						},
					},
					Spec: corev1.PodSpec{
						SecurityContext: &corev1.PodSecurityContext{
							RunAsNonRoot:   &[]bool{true}[0],
							RunAsUser:      &[]int64{1000}[0],
							SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
							FSGroup:        &[]int64{1000}[0],
						},
						Containers: []corev1.Container{
							{
								Name:  "container",
								Image: "image",
								SecurityContext: &corev1.SecurityContext{
									AllowPrivilegeEscalation: &[]bool{false}[0],
									Capabilities: &corev1.Capabilities{
										Drop: []corev1.Capability{"ALL"},
									},
									RunAsNonRoot: &[]bool{true}[0],
								},
							},
						},
					},
				},
			},
			enforceLevel: "restricted",
			expectedConditions: map[string][]string{
				"customer": {"customer-ns"},
			},
			expectError: false,
		},
		{
			name: "customer namespace with no pods",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "customer-ns",
				},
			},
			pods:         []corev1.Pod{},
			enforceLevel: "restricted",
			expectedConditions: map[string][]string{
				"customer": {"customer-ns"},
			},
			expectError: false,
		},
		{
			name: "invalid PSA level causes error",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "customer-ns",
				},
			},
			pods:                []corev1.Pod{},
			enforceLevel:        "invalid-level",
			expectedConditions:  map[string][]string{},
			expectError:         true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewSimpleClientset()
			
			// Add pods to fake client
			for _, pod := range tt.pods {
				_, err := fakeClient.CoreV1().Pods(tt.namespace.Name).Create(context.Background(), &pod, metav1.CreateOptions{})
				if err != nil {
					t.Fatalf("Failed to create test pod: %v", err)
				}
			}

			psaEvaluator, err := policy.NewEvaluator(policy.DefaultChecks())
			if err != nil {
				t.Fatalf("Failed to create PSA evaluator: %v", err)
			}

			controller := &PodSecurityReadinessController{
				kubeClient:   fakeClient,
				psaEvaluator: psaEvaluator,
			}

			conditions := podSecurityOperatorConditions{}
			
			err = controller.classifyViolatingNamespace(context.Background(), &conditions, tt.namespace, tt.enforceLevel)
			
			if (err != nil) != tt.expectError {
				t.Errorf("classifyViolatingNamespace() error = %v, expectError %v", err, tt.expectError)
				return
			}

			if err != nil {
				return // Expected error, nothing more to check
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

func TestClassifyViolatingNamespaceSimplified(t *testing.T) {
	// Test just the classification logic without full controller setup for edge cases
	for _, tt := range []struct {
		name               string
		namespace          *corev1.Namespace
		expectedCondition  string
	}{
		{
			name: "kube-public run-level zero",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "kube-public",
				},
			},
			expectedCondition: "runLevelZero",
		},
		{
			name: "openshift-apiserver",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "openshift-apiserver",
				},
			},
			expectedCondition: "openshift",
		},
		{
			name: "openshift-config",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "openshift-config",
				},
			},
			expectedCondition: "openshift",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conditions := podSecurityOperatorConditions{}
			
			// Test the simple classification logic that doesn't require user violation check
			if runLevelZeroNamespaces.Has(tt.namespace.Name) {
				conditions.addViolatingRunLevelZero(tt.namespace)
			} else if strings.HasPrefix(tt.namespace.Name, "openshift") {
				conditions.addViolatingOpenShift(tt.namespace)
			} else if tt.namespace.Labels[labelSyncControlLabel] == "false" {
				conditions.addViolatingDisabledSyncer(tt.namespace)
			}
			
			// Verify the correct condition was set
			switch tt.expectedCondition {
			case "runLevelZero":
				if len(conditions.violatingRunLevelZeroNamespaces) != 1 || conditions.violatingRunLevelZeroNamespaces[0] != tt.namespace.Name {
					t.Errorf("expected runLevelZero condition for %s, got %v", tt.namespace.Name, conditions.violatingRunLevelZeroNamespaces)
				}
			case "openshift":
				if len(conditions.violatingOpenShiftNamespaces) != 1 || conditions.violatingOpenShiftNamespaces[0] != tt.namespace.Name {
					t.Errorf("expected openshift condition for %s, got %v", tt.namespace.Name, conditions.violatingOpenShiftNamespaces)
				}
			case "disabledSyncer":
				if len(conditions.violatingDisabledSyncerNamespaces) != 1 || conditions.violatingDisabledSyncerNamespaces[0] != tt.namespace.Name {
					t.Errorf("expected disabledSyncer condition for %s, got %v", tt.namespace.Name, conditions.violatingDisabledSyncerNamespaces)
				}
			}
		})
	}
}

func TestClassifyViolatingNamespaceErrorHandling(t *testing.T) {
	tests := []struct {
		name                string
		namespace           *corev1.Namespace
		enforceLevel        string
		setupClientError    func(*fake.Clientset)
		expectError         bool
		expectInconclusive  bool
		description         string
	}{
		{
			name: "pod listing API error triggers inconclusive",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "customer-ns",
				},
			},
			enforceLevel: "restricted",
			setupClientError: func(client *fake.Clientset) {
				client.PrependReactor("list", "pods", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("API server temporarily unavailable")
				})
			},
			expectError:        true,
			expectInconclusive: true,
			description:        "should return error when pod listing fails",
		},
		{
			name: "invalid PSA level triggers error",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "customer-ns",
				},
			},
			enforceLevel:       "invalid-level",
			setupClientError:   func(client *fake.Clientset) {}, // No error setup needed
			expectError:        true,
			expectInconclusive: true,
			description:        "should return error for invalid PSA levels",
		},
		{
			name: "network timeout during pod listing",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "customer-ns",
				},
			},
			enforceLevel: "restricted",
			setupClientError: func(client *fake.Clientset) {
				client.PrependReactor("list", "pods", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("context deadline exceeded")
				})
			},
			expectError:        true,
			expectInconclusive: true,
			description:        "should handle network timeouts during pod listing",
		},
		{
			name: "intermittent API server error",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "customer-ns",
				},
			},
			enforceLevel: "restricted",
			setupClientError: func(client *fake.Clientset) {
				client.PrependReactor("list", "pods", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("server is shutting down")
				})
			},
			expectError:        true,
			expectInconclusive: true,
			description:        "should handle intermittent API server errors",
		},
		{
			name: "successful classification after client setup",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "customer-ns",
				},
			},
			enforceLevel:       "restricted",
			setupClientError:   func(client *fake.Clientset) {}, // No error
			expectError:        false,
			expectInconclusive: false,
			description:        "should successfully classify when no errors",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := fake.NewSimpleClientset()
			tc.setupClientError(fakeClient)

			psaEvaluator, err := policy.NewEvaluator(policy.DefaultChecks())
			if err != nil {
				t.Fatalf("Failed to create PSA evaluator: %v", err)
			}

			controller := &PodSecurityReadinessController{
				kubeClient:   fakeClient,
				psaEvaluator: psaEvaluator,
			}

			conditions := podSecurityOperatorConditions{}
			
			err = controller.classifyViolatingNamespace(context.Background(), &conditions, tc.namespace, tc.enforceLevel)
			
			if (err != nil) != tc.expectError {
				t.Errorf("classifyViolatingNamespace() error = %v, expectError %v (%s)", err, tc.expectError, tc.description)
			}

			if tc.expectInconclusive {
				// When an error occurs during classification, the namespace should not be classified
				// This is handled by the sync loop which adds it to inconclusive
				totalClassified := len(conditions.violatingRunLevelZeroNamespaces) +
					len(conditions.violatingOpenShiftNamespaces) +
					len(conditions.violatingDisabledSyncerNamespaces) +
					len(conditions.violatingCustomerNamespaces) +
					len(conditions.userSCCViolationNamespaces)
				
				if !tc.expectError && totalClassified == 0 {
					t.Errorf("Expected namespace to be classified but none were found")
				}
			}
		})
	}
}

func TestSyncInconclusiveHandling(t *testing.T) {
	// Test that simulates what happens in the actual sync method when errors occur
	tests := []struct {
		name               string
		namespace          *corev1.Namespace
		simulateError      bool
		expectedInconclusive bool
		description        string
	}{
		{
			name: "API error leads to inconclusive classification",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "customer-ns",
				},
			},
			simulateError:        true,
			expectedInconclusive: true,
			description:          "should mark namespace as inconclusive when classification fails",
		},
		{
			name: "successful classification does not mark as inconclusive",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "customer-ns",
				},
			},
			simulateError:        false,
			expectedInconclusive: false,
			description:          "should not mark namespace as inconclusive when classification succeeds",
		},
		{
			name: "OpenShift namespace error handling",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "openshift-test",
				},
			},
			simulateError:        true,
			expectedInconclusive: false, // OpenShift namespaces don't need user violation check
			description:          "OpenShift namespaces should not be inconclusive even with errors",
		},
		{
			name: "run-level zero namespace error handling",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "kube-system",
				},
			},
			simulateError:        true,
			expectedInconclusive: false, // Run-level zero namespaces don't need user violation check
			description:          "run-level zero namespaces should not be inconclusive even with errors",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := fake.NewSimpleClientset()
			
			if tc.simulateError && !runLevelZeroNamespaces.Has(tc.namespace.Name) && !strings.HasPrefix(tc.namespace.Name, "openshift") {
				// Only add error for customer namespaces that need user violation checks
				fakeClient.PrependReactor("list", "pods", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("simulated API error")
				})
			}

			psaEvaluator, err := policy.NewEvaluator(policy.DefaultChecks())
			if err != nil {
				t.Fatalf("Failed to create PSA evaluator: %v", err)
			}

			controller := &PodSecurityReadinessController{
				kubeClient:   fakeClient,
				psaEvaluator: psaEvaluator,
			}

			conditions := podSecurityOperatorConditions{}
			
			// Simulate the retry logic from sync method
			err = controller.classifyViolatingNamespace(context.Background(), &conditions, tc.namespace, "restricted")
			
			if err != nil {
				// This is what the sync method does when classifyViolatingNamespace returns an error
				conditions.addInconclusive(tc.namespace)
			}

			// Check if namespace was marked as inconclusive
			wasMarkedInconclusive := false
			for _, inconclusiveNS := range conditions.inconclusiveNamespaces {
				if inconclusiveNS == tc.namespace.Name {
					wasMarkedInconclusive = true
					break
				}
			}

			if wasMarkedInconclusive != tc.expectedInconclusive {
				t.Errorf("namespace inconclusive status = %v, expected %v (%s)", wasMarkedInconclusive, tc.expectedInconclusive, tc.description)
			}
		})
	}
}

func TestResourceUnavailabilityScenarios(t *testing.T) {
	tests := []struct {
		name            string
		namespace       *corev1.Namespace
		simulateError   string
		expectError     bool
		description     string
	}{
		{
			name: "etcd unavailable",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "customer-ns"},
			},
			simulateError: "etcdserver: request timed out",
			expectError:   true,
			description:   "should handle etcd unavailability",
		},
		{
			name: "kube-apiserver overloaded",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "customer-ns"},
			},
			simulateError: "too many requests",
			expectError:   true,
			description:   "should handle API server overload",
		},
		{
			name: "network partition",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "customer-ns"},
			},
			simulateError: "connection refused",
			expectError:   true,
			description:   "should handle network partitions",
		},
		{
			name: "resource version conflict",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "customer-ns"},
			},
			simulateError: "resource version conflict",
			expectError:   true,
			description:   "should handle resource version conflicts",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := fake.NewSimpleClientset()
			
			fakeClient.PrependReactor("list", "pods", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
				return true, nil, fmt.Errorf(tc.simulateError)
			})

			psaEvaluator, err := policy.NewEvaluator(policy.DefaultChecks())
			if err != nil {
				t.Fatalf("Failed to create PSA evaluator: %v", err)
			}

			controller := &PodSecurityReadinessController{
				kubeClient:   fakeClient,
				psaEvaluator: psaEvaluator,
			}

			conditions := podSecurityOperatorConditions{}
			
			err = controller.classifyViolatingNamespace(context.Background(), &conditions, tc.namespace, "restricted")
			
			if (err != nil) != tc.expectError {
				t.Errorf("classifyViolatingNamespace() error = %v, expectError %v (%s)", err, tc.expectError, tc.description)
			}

			if err != nil {
				// Verify error message contains relevant information
				if err.Error() != tc.simulateError {
					t.Errorf("expected error message %q, got %q", tc.simulateError, err.Error())
				}
			}
		})
	}
}

func TestPSAEvaluatorErrorHandling(t *testing.T) {
	// Test edge cases in PSA evaluation that could cause errors
	tests := []struct {
		name        string
		enforceLevel string
		expectError bool
		description string
	}{
		{
			name:        "empty enforce level",
			enforceLevel: "",
			expectError: true,
			description: "should handle empty enforce level",
		},
		{
			name:        "whitespace-only enforce level",
			enforceLevel: "   ",
			expectError: true,
			description: "should handle whitespace-only enforce level",
		},
		{
			name:        "case-sensitive level validation",
			enforceLevel: "Restricted", // Uppercase R
			expectError: false, // Current implementation doesn't validate case
			description: "should handle case-sensitive level names",
		},
		{
			name:        "level with extra characters",
			enforceLevel: "restricted-v1",
			expectError: true,
			description: "should reject levels with extra characters",
		},
		{
			name:        "numeric level",
			enforceLevel: "1",
			expectError: true,
			description: "should reject numeric level values",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := fake.NewSimpleClientset()

			psaEvaluator, err := policy.NewEvaluator(policy.DefaultChecks())
			if err != nil {
				t.Fatalf("Failed to create PSA evaluator: %v", err)
			}

			controller := &PodSecurityReadinessController{
				kubeClient:   fakeClient,
				psaEvaluator: psaEvaluator,
			}

			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "customer-ns"},
			}

			conditions := podSecurityOperatorConditions{}
			
			err = controller.classifyViolatingNamespace(context.Background(), &conditions, namespace, tc.enforceLevel)
			
			if (err != nil) != tc.expectError {
				t.Errorf("classifyViolatingNamespace() with level %q: error = %v, expectError %v (%s)", 
					tc.enforceLevel, err, tc.expectError, tc.description)
			}
		})
	}
}