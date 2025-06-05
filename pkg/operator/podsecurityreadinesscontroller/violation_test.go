package podsecurityreadinesscontroller

import (
	"context"
	"fmt"
	"testing"

	securityv1 "github.com/openshift/api/security/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	applyconfiguration "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	clienttesting "k8s.io/client-go/testing"
	psapi "k8s.io/pod-security-admission/api"
	"k8s.io/pod-security-admission/policy"
)

// Need to add managed fields to mock namespaces, since violations are only checked for labels managed by the syncer
var managedFields = []metav1.ManagedFieldsEntry{
	{
		Manager:   syncerControllerName,
		Operation: "Apply",
		FieldsV1: &metav1.FieldsV1{
			Raw: []byte(
				fmt.Sprintf(`{"f:metadata":{"f:annotations":{"f:%s":{}},"f:labels":{"f:%s":{},"f:%s":{},"f:%s":{}}}}`,
					securityv1.MinimallySufficientPodSecurityStandard,
					psapi.WarnLevelLabel,
					psapi.AuditLevelLabel,
					psapi.EnforceLevelLabel,
				),
			),
		},
	},
}

func TestIsNamespaceViolating(t *testing.T) {
	tests := []struct {
		name            string
		namespace       *corev1.Namespace
		warnings        []string
		setupMockClient func() kubernetes.Interface
		expectViolating bool
		expectError     bool
	}{
		{
			name: "namespace with MinimallySufficientPodSecurityStandard annotation and no violations",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-ns-1",
					Annotations: map[string]string{
						securityv1.MinimallySufficientPodSecurityStandard: "restricted",
					},
				},
			},
			warnings: []string{},
			setupMockClient: func() kubernetes.Interface {
				return &mockKubeClientWithResponse{}
			},
			expectViolating: false,
			expectError:     false,
		},
		{
			name: "namespace with MinimallySufficientPodSecurityStandard annotation and violations",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-ns-2",
					Annotations: map[string]string{
						securityv1.MinimallySufficientPodSecurityStandard: "restricted",
					},
				},
			},
			warnings: []string{"violation found"},
			setupMockClient: func() kubernetes.Interface {
				return &mockKubeClientWithResponse{}
			},
			expectViolating: true,
			expectError:     false,
		},
		{
			name: "namespace with no annotation defaults to restricted",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "test-ns-5",
					Labels: map[string]string{},
				},
			},
			warnings: []string{},
			setupMockClient: func() kubernetes.Interface {
				return &mockKubeClientWithResponse{}
			},
			expectViolating: false,
			expectError:     false,
		},
		{
			name: "Apply returns error",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-ns-6",
					Annotations: map[string]string{
						securityv1.MinimallySufficientPodSecurityStandard: "restricted",
					},
				},
			},
			warnings: []string{},
			setupMockClient: func() kubernetes.Interface {
				return &mockKubeClientWithResponse{
					error: fmt.Errorf("apply error"),
				}
			},
			expectViolating: false,
			expectError:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockWarnings := &warningsHandler{
				warnings: tc.warnings,
			}

			psaEvaluator, err := policy.NewEvaluator(policy.DefaultChecks())
			if err != nil {
				t.Fatalf("Failed to create PSA evaluator: %v", err)
			}

			controller := &PodSecurityReadinessController{
				kubeClient:      tc.setupMockClient(),
				warningsHandler: mockWarnings,
				psaEvaluator:    psaEvaluator,
			}

			tc.namespace.ManagedFields = managedFields

			violating, _, err := controller.isNamespaceViolating(context.Background(), tc.namespace)

			if (err != nil) != tc.expectError {
				t.Errorf("isNamespaceViolating() error = %v, expectError %v", err, tc.expectError)
				return
			}

			if violating != tc.expectViolating {
				t.Errorf("isNamespaceViolating() violating = %v, expectViolating %v", violating, tc.expectViolating)
			}
		})
	}
}

type mockKubeClientWithResponse struct {
	kubernetes.Interface
	error error
}

func (m *mockKubeClientWithResponse) CoreV1() typedcorev1.CoreV1Interface {
	return &mockCoreV1WithResponse{error: m.error}
}

type mockCoreV1WithResponse struct {
	typedcorev1.CoreV1Interface
	error error
}

func (m *mockCoreV1WithResponse) Namespaces() typedcorev1.NamespaceInterface {
	return &mockNamespaceInterfaceWithResponse{error: m.error}
}

func (m *mockCoreV1WithResponse) Pods(namespace string) typedcorev1.PodInterface {
	return &mockPodInterface{error: m.error}
}

type mockNamespaceInterfaceWithResponse struct {
	typedcorev1.NamespaceInterface
	error error
}

func (m *mockNamespaceInterfaceWithResponse) Apply(ctx context.Context, nsApply *applyconfiguration.NamespaceApplyConfiguration, opts metav1.ApplyOptions) (*corev1.Namespace, error) {
	return nil, m.error
}

type mockPodInterface struct {
	typedcorev1.PodInterface
	error error
}

func (m *mockPodInterface) List(ctx context.Context, opts metav1.ListOptions) (*corev1.PodList, error) {
	if m.error != nil {
		return nil, m.error
	}
	return &corev1.PodList{}, nil
}

func TestDetermineEnforceLabelForNamespace(t *testing.T) {
	tests := []struct {
		name                string
		namespace           *applyconfiguration.NamespaceApplyConfiguration
		expectedEnforceLevel string
	}{
		{
			name: "namespace with MinimallySufficientPodSecurityStandard annotation - restricted",
			namespace: applyconfiguration.Namespace("test-ns").
				WithAnnotations(map[string]string{
					securityv1.MinimallySufficientPodSecurityStandard: "restricted",
				}),
			expectedEnforceLevel: "restricted",
		},
		{
			name: "namespace with MinimallySufficientPodSecurityStandard annotation - baseline",
			namespace: applyconfiguration.Namespace("test-ns").
				WithAnnotations(map[string]string{
					securityv1.MinimallySufficientPodSecurityStandard: "baseline",
				}),
			expectedEnforceLevel: "baseline",
		},
		{
			name: "namespace with MinimallySufficientPodSecurityStandard annotation - privileged",
			namespace: applyconfiguration.Namespace("test-ns").
				WithAnnotations(map[string]string{
					securityv1.MinimallySufficientPodSecurityStandard: "privileged",
				}),
			expectedEnforceLevel: "privileged",
		},
		{
			name: "namespace with PSA warn label only",
			namespace: applyconfiguration.Namespace("test-ns").
				WithLabels(map[string]string{
					psapi.WarnLevelLabel: "baseline",
				}),
			expectedEnforceLevel: "baseline",
		},
		{
			name: "namespace with PSA audit label only",
			namespace: applyconfiguration.Namespace("test-ns").
				WithLabels(map[string]string{
					psapi.AuditLevelLabel: "restricted",
				}),
			expectedEnforceLevel: "restricted",
		},
		{
			name: "namespace with both warn and audit labels - more restrictive wins",
			namespace: applyconfiguration.Namespace("test-ns").
				WithLabels(map[string]string{
					psapi.WarnLevelLabel:  "baseline",
					psapi.AuditLevelLabel: "restricted",
				}),
			expectedEnforceLevel: "restricted",
		},
		{
			name: "namespace with both warn and audit labels - more restrictive wins (reverse)",
			namespace: applyconfiguration.Namespace("test-ns").
				WithLabels(map[string]string{
					psapi.WarnLevelLabel:  "restricted",
					psapi.AuditLevelLabel: "baseline",
				}),
			expectedEnforceLevel: "restricted",
		},
		{
			name: "annotation takes priority over PSA labels",
			namespace: applyconfiguration.Namespace("test-ns").
				WithAnnotations(map[string]string{
					securityv1.MinimallySufficientPodSecurityStandard: "baseline",
				}).
				WithLabels(map[string]string{
					psapi.WarnLevelLabel:  "restricted",
					psapi.AuditLevelLabel: "restricted",
				}),
			expectedEnforceLevel: "baseline",
		},
		{
			name: "privileged vs restricted - privileged is less restrictive",
			namespace: applyconfiguration.Namespace("test-ns").
				WithLabels(map[string]string{
					psapi.WarnLevelLabel:  "privileged",
					psapi.AuditLevelLabel: "restricted",
				}),
			expectedEnforceLevel: "restricted",
		},
		{
			name: "privileged vs baseline - baseline is more restrictive",
			namespace: applyconfiguration.Namespace("test-ns").
				WithLabels(map[string]string{
					psapi.WarnLevelLabel:  "privileged",
					psapi.AuditLevelLabel: "baseline",
				}),
			expectedEnforceLevel: "baseline",
		},
		{
			name: "namespace with no annotations or PSA labels defaults to restricted",
			namespace: applyconfiguration.Namespace("test-ns"),
			expectedEnforceLevel: "restricted",
		},
		{
			name: "namespace with empty annotations and labels defaults to restricted",
			namespace: applyconfiguration.Namespace("test-ns").
				WithAnnotations(map[string]string{}).
				WithLabels(map[string]string{}),
			expectedEnforceLevel: "restricted",
		},
		{
			name: "namespace with other annotations but no PSA annotation defaults to restricted",
			namespace: applyconfiguration.Namespace("test-ns").
				WithAnnotations(map[string]string{
					"some.other/annotation": "value",
				}),
			expectedEnforceLevel: "restricted",
		},
		{
			name: "namespace with other labels but no PSA labels defaults to restricted",
			namespace: applyconfiguration.Namespace("test-ns").
				WithLabels(map[string]string{
					"some.other/label": "value",
				}),
			expectedEnforceLevel: "restricted",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enforceLevel := determineEnforceLabelForNamespace(tc.namespace)
			
			if enforceLevel != tc.expectedEnforceLevel {
				t.Errorf("determineEnforceLabelForNamespace() = %v, expected %v", enforceLevel, tc.expectedEnforceLevel)
			}
		})
	}
}

func TestDetermineEnforceLabelForNamespaceWithInvalidValues(t *testing.T) {
	tests := []struct {
		name                 string
		namespace            *applyconfiguration.NamespaceApplyConfiguration
		expectedEnforceLevel string
		description          string
	}{
		{
			name: "invalid PSA level in warn label",
			namespace: applyconfiguration.Namespace("test-ns").
				WithLabels(map[string]string{
					psapi.WarnLevelLabel:  "invalid-level",
					psapi.AuditLevelLabel: "restricted",
				}),
			expectedEnforceLevel: "restricted",
			description:          "should ignore invalid level and use valid audit level",
		},
		{
			name: "invalid PSA level in audit label",
			namespace: applyconfiguration.Namespace("test-ns").
				WithLabels(map[string]string{
					psapi.WarnLevelLabel:  "baseline",
					psapi.AuditLevelLabel: "invalid-level",
				}),
			expectedEnforceLevel: "baseline",
			description:          "should ignore invalid level and use valid warn level",
		},
		{
			name: "both PSA labels invalid",
			namespace: applyconfiguration.Namespace("test-ns").
				WithLabels(map[string]string{
					psapi.WarnLevelLabel:  "invalid-level1",
					psapi.AuditLevelLabel: "invalid-level2",
				}),
			expectedEnforceLevel: "restricted",
			description:          "should default to restricted when all PSA labels are invalid",
		},
		{
			name: "empty PSA label values",
			namespace: applyconfiguration.Namespace("test-ns").
				WithLabels(map[string]string{
					psapi.WarnLevelLabel:  "",
					psapi.AuditLevelLabel: "",
				}),
			expectedEnforceLevel: "restricted",
			description:          "should default to restricted when PSA labels are empty",
		},
		{
			name: "mixed valid and empty PSA labels",
			namespace: applyconfiguration.Namespace("test-ns").
				WithLabels(map[string]string{
					psapi.WarnLevelLabel:  "baseline",
					psapi.AuditLevelLabel: "",
				}),
			expectedEnforceLevel: "baseline",
			description:          "should use valid label and ignore empty one",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enforceLevel := determineEnforceLabelForNamespace(tc.namespace)
			
			if enforceLevel != tc.expectedEnforceLevel {
				t.Errorf("determineEnforceLabelForNamespace() = %v, expected %v (%s)", enforceLevel, tc.expectedEnforceLevel, tc.description)
			}
		})
	}
}

func TestDetermineEnforceLabelForNamespaceWithManagedFields(t *testing.T) {
	// This test verifies behavior with different managed field scenarios,
	// although the current implementation doesn't use managed fields for determination,
	// it's important to document the expected behavior.
	
	tests := []struct {
		name                 string
		namespace            *applyconfiguration.NamespaceApplyConfiguration
		expectedEnforceLevel string
		description          string
	}{
		{
			name: "annotation with mixed source managed fields",
			namespace: applyconfiguration.Namespace("test-ns").
				WithAnnotations(map[string]string{
					securityv1.MinimallySufficientPodSecurityStandard: "baseline",
				}).
				WithLabels(map[string]string{
					psapi.WarnLevelLabel:  "restricted",
					psapi.AuditLevelLabel: "restricted",
				}),
			expectedEnforceLevel: "baseline",
			description:          "annotation should take priority regardless of managed fields",
		},
		{
			name: "labels only with user managed fields",
			namespace: applyconfiguration.Namespace("test-ns").
				WithLabels(map[string]string{
					psapi.WarnLevelLabel:  "privileged",
					psapi.AuditLevelLabel: "baseline",
				}),
			expectedEnforceLevel: "baseline",
			description:          "should use more restrictive level from available labels",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enforceLevel := determineEnforceLabelForNamespace(tc.namespace)
			
			if enforceLevel != tc.expectedEnforceLevel {
				t.Errorf("determineEnforceLabelForNamespace() = %v, expected %v (%s)", enforceLevel, tc.expectedEnforceLevel, tc.description)
			}
		})
	}
}

func TestDetermineEnforceLabelEdgeCases(t *testing.T) {
	tests := []struct {
		name                 string
		namespace            *applyconfiguration.NamespaceApplyConfiguration
		expectedEnforceLevel string
	}{
		{
			name: "namespace with same level in annotation and labels",
			namespace: applyconfiguration.Namespace("test-ns").
				WithAnnotations(map[string]string{
					securityv1.MinimallySufficientPodSecurityStandard: "restricted",
				}).
				WithLabels(map[string]string{
					psapi.WarnLevelLabel:  "restricted",
					psapi.AuditLevelLabel: "restricted",
				}),
			expectedEnforceLevel: "restricted",
		},
		{
			name: "namespace with privileged in all fields",
			namespace: applyconfiguration.Namespace("test-ns").
				WithAnnotations(map[string]string{
					securityv1.MinimallySufficientPodSecurityStandard: "privileged",
				}).
				WithLabels(map[string]string{
					psapi.WarnLevelLabel:  "privileged",
					psapi.AuditLevelLabel: "privileged",
				}),
			expectedEnforceLevel: "privileged",
		},
		{
			name: "namespace with case sensitivity test",
			namespace: applyconfiguration.Namespace("test-ns").
				WithLabels(map[string]string{
					psapi.WarnLevelLabel: "Baseline", // Uppercase B
				}),
			expectedEnforceLevel: "restricted", // Should be invalid and default to restricted
		},
		{
			name: "namespace with extra whitespace in levels",
			namespace: applyconfiguration.Namespace("test-ns").
				WithLabels(map[string]string{
					psapi.WarnLevelLabel: " baseline ", // With spaces
				}),
			expectedEnforceLevel: "restricted", // Should be invalid and default to restricted
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enforceLevel := determineEnforceLabelForNamespace(tc.namespace)
			
			if enforceLevel != tc.expectedEnforceLevel {
				t.Errorf("determineEnforceLabelForNamespace() = %v, expected %v", enforceLevel, tc.expectedEnforceLevel)
			}
		})
	}
}
func TestIsUserViolation(t *testing.T) {
	tests := []struct {
		name             string
		namespace        *corev1.Namespace
		pods             []corev1.Pod
		enforceLevel     string
		expectViolation  bool
		expectError      bool
		setupMockClient  func() *fake.Clientset
	}{
		{
			name: "no pods in namespace",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-ns"},
			},
			pods:            []corev1.Pod{},
			enforceLevel:    "restricted",
			expectViolation: false,
			expectError:     false,
			setupMockClient: func() *fake.Clientset {
				return fake.NewSimpleClientset()
			},
		},
		{
			name: "only service account pods - no user violations",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-ns"},
			},
			pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sa-pod",
						Namespace: "test-ns",
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
			enforceLevel:    "restricted",
			expectViolation: false,
			expectError:     false,
			setupMockClient: func() *fake.Clientset {
				return fake.NewSimpleClientset()
			},
		},
		{
			name: "user pod violates restricted level",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-ns"},
			},
			pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "user-pod",
						Namespace: "test-ns",
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
			enforceLevel:    "restricted",
			expectViolation: true,
			expectError:     false,
			setupMockClient: func() *fake.Clientset {
				return fake.NewSimpleClientset()
			},
		},
		{
			name: "user pod passes restricted level",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-ns"},
			},
			pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "user-pod",
						Namespace: "test-ns",
						Annotations: map[string]string{
							securityv1.ValidatedSCCSubjectTypeAnnotation: "user",
						},
					},
					Spec: corev1.PodSpec{
						SecurityContext: &corev1.PodSecurityContext{
							RunAsNonRoot:     &[]bool{true}[0],
							RunAsUser:        &[]int64{1000}[0],
							SeccompProfile:   &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
							FSGroup:          &[]int64{1000}[0],
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
			enforceLevel:    "restricted",
			expectViolation: false,
			expectError:     false,
			setupMockClient: func() *fake.Clientset {
				return fake.NewSimpleClientset()
			},
		},
		{
			name: "user pod violates baseline level",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-ns"},
			},
			pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "user-pod",
						Namespace: "test-ns",
						Annotations: map[string]string{
							securityv1.ValidatedSCCSubjectTypeAnnotation: "user",
						},
					},
					Spec: corev1.PodSpec{
						HostNetwork: true,
						Containers: []corev1.Container{
							{
								Name:  "container",
								Image: "image",
							},
						},
					},
				},
			},
			enforceLevel:    "baseline",
			expectViolation: true,
			expectError:     false,
			setupMockClient: func() *fake.Clientset {
				return fake.NewSimpleClientset()
			},
		},
		{
			name: "user pod passes baseline level",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-ns"},
			},
			pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "user-pod",
						Namespace: "test-ns",
						Annotations: map[string]string{
							securityv1.ValidatedSCCSubjectTypeAnnotation: "user",
						},
					},
					Spec: corev1.PodSpec{
						SecurityContext: &corev1.PodSecurityContext{
							RunAsUser: &[]int64{1000}[0],
						},
						Containers: []corev1.Container{
							{
								Name:  "container",
								Image: "image",
							},
						},
					},
				},
			},
			enforceLevel:    "baseline",
			expectViolation: false,
			expectError:     false,
			setupMockClient: func() *fake.Clientset {
				return fake.NewSimpleClientset()
			},
		},
		{
			name: "privileged level always returns false",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-ns"},
			},
			pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "user-pod",
						Namespace: "test-ns",
						Annotations: map[string]string{
							securityv1.ValidatedSCCSubjectTypeAnnotation: "user",
						},
					},
					Spec: corev1.PodSpec{
						HostNetwork: true,
						Containers: []corev1.Container{
							{
								Name:  "container",
								Image: "image",
								SecurityContext: &corev1.SecurityContext{
									Privileged: &[]bool{true}[0],
								},
							},
						},
					},
				},
			},
			enforceLevel:    "privileged",
			expectViolation: false,
			expectError:     false,
			setupMockClient: func() *fake.Clientset {
				return fake.NewSimpleClientset()
			},
		},
		{
			name: "mixed user and service account pods - user violates",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-ns"},
			},
			pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "sa-pod",
						Namespace: "test-ns",
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
						Namespace: "test-ns",
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
			enforceLevel:    "restricted",
			expectViolation: true,
			expectError:     false,
			setupMockClient: func() *fake.Clientset {
				return fake.NewSimpleClientset()
			},
		},
		{
			name: "invalid PSA level",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-ns"},
			},
			pods:            []corev1.Pod{},
			enforceLevel:    "invalid-level",
			expectViolation: false,
			expectError:     true,
			setupMockClient: func() *fake.Clientset {
				return fake.NewSimpleClientset()
			},
		},
		{
			name: "pod listing error",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-ns"},
			},
			pods:            []corev1.Pod{},
			enforceLevel:    "restricted",
			expectViolation: false,
			expectError:     true,
			setupMockClient: func() *fake.Clientset {
				fakeClient := fake.NewSimpleClientset()
				fakeClient.PrependReactor("list", "pods", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("api server error")
				})
				return fakeClient
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := tc.setupMockClient()
			
			// Add pods to fake client
			for _, pod := range tc.pods {
				_, err := fakeClient.CoreV1().Pods(tc.namespace.Name).Create(context.Background(), &pod, metav1.CreateOptions{})
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

			violating, err := controller.isUserViolation(context.Background(), tc.namespace, tc.enforceLevel)

			if (err != nil) != tc.expectError {
				t.Errorf("isUserViolation() error = %v, expectError %v", err, tc.expectError)
				return
			}

			if violating != tc.expectViolation {
				t.Errorf("isUserViolation() violating = %v, expectViolation %v", violating, tc.expectViolation)
			}
		})
	}
}

func TestIsUserViolationEdgeCases(t *testing.T) {
	tests := []struct {
		name            string
		namespace       *corev1.Namespace
		pod             *corev1.Pod
		enforceLevel    string
		expectViolation bool
		expectError     bool
	}{
		{
			name: "pod with no annotation defaults to service account",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-ns"},
			},
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "no-annotation-pod",
					Namespace: "test-ns",
				},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: &[]bool{false}[0],
					},
				},
			},
			enforceLevel:    "restricted",
			expectViolation: false,
			expectError:     false,
		},
		{
			name: "pod with empty annotation value defaults to service account",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-ns"},
			},
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "empty-annotation-pod",
					Namespace: "test-ns",
					Annotations: map[string]string{
						securityv1.ValidatedSCCSubjectTypeAnnotation: "",
					},
				},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: &[]bool{false}[0],
					},
				},
			},
			enforceLevel:    "restricted",
			expectViolation: false,
			expectError:     false,
		},
		{
			name: "pod with system:master annotation treated as user",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-ns"},
			},
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "system-master-pod",
					Namespace: "test-ns",
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
			enforceLevel:    "restricted",
			expectViolation: true,
			expectError:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := fake.NewSimpleClientset()
			
			if tc.pod != nil {
				_, err := fakeClient.CoreV1().Pods(tc.namespace.Name).Create(context.Background(), tc.pod, metav1.CreateOptions{})
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

			violating, err := controller.isUserViolation(context.Background(), tc.namespace, tc.enforceLevel)

			if (err != nil) != tc.expectError {
				t.Errorf("isUserViolation() error = %v, expectError %v", err, tc.expectError)
				return
			}

			if violating != tc.expectViolation {
				t.Errorf("isUserViolation() violating = %v, expectViolation %v", violating, tc.expectViolation)
			}
		})
	}
}

func TestMalformedNamespaceConfigurations(t *testing.T) {
	tests := []struct {
		name                 string
		namespace            *corev1.Namespace
		expectedEnforceLevel string
		description          string
	}{
		{
			name: "namespace with corrupted annotation value",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "malformed-ns",
					Annotations: map[string]string{
						securityv1.MinimallySufficientPodSecurityStandard: "corrupted-value-!@#$%",
					},
				},
			},
			expectedEnforceLevel: "corrupted-value-!@#$%", // Current implementation returns as-is
			description:          "should handle corrupted annotation values",
		},
		{
			name: "namespace with unicode annotation value",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "unicode-ns",
					Annotations: map[string]string{
						securityv1.MinimallySufficientPodSecurityStandard: "рестрикт", // Cyrillic
					},
				},
			},
			expectedEnforceLevel: "рестрикт",
			description:          "should handle unicode annotation values",
		},
		{
			name: "namespace with very long annotation value",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "long-annotation-ns",
					Annotations: map[string]string{
						securityv1.MinimallySufficientPodSecurityStandard: "restricted" + string(make([]byte, 1000)), // Very long value
					},
				},
			},
			expectedEnforceLevel: "restricted" + string(make([]byte, 1000)),
			description:          "should handle very long annotation values",
		},
		{
			name: "namespace with null byte in annotation",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "null-byte-ns",
					Annotations: map[string]string{
						securityv1.MinimallySufficientPodSecurityStandard: "restricted\x00baseline",
					},
				},
			},
			expectedEnforceLevel: "restricted\x00baseline",
			description:          "should handle null bytes in annotation values",
		},
		{
			name: "namespace with mixed case PSA labels",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "mixed-case-ns",
					Labels: map[string]string{
						psapi.WarnLevelLabel:  "BASELINE",  // Uppercase
						psapi.AuditLevelLabel: "Restricted", // Mixed case
					},
				},
			},
			expectedEnforceLevel: "restricted", // Should default to restricted for invalid levels
			description:          "should handle mixed case PSA label values",
		},
		{
			name: "namespace with standard annotation",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "standard-ns",
					Annotations: map[string]string{
						securityv1.MinimallySufficientPodSecurityStandard: "baseline",
					},
				},
			},
			expectedEnforceLevel: "baseline",
			description:          "should handle standard annotation correctly",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create namespace apply configuration directly with all fields
			nsApply := applyconfiguration.Namespace(tc.namespace.Name)
			if tc.namespace.Annotations != nil {
				nsApply.WithAnnotations(tc.namespace.Annotations)
			}
			if tc.namespace.Labels != nil {
				nsApply.WithLabels(tc.namespace.Labels)
			}

			enforceLevel := determineEnforceLabelForNamespace(nsApply)
			
			if enforceLevel != tc.expectedEnforceLevel {
				t.Errorf("determineEnforceLabelForNamespace() = %v, expected %v (%s)", 
					enforceLevel, tc.expectedEnforceLevel, tc.description)
			}
		})
	}
}

func TestMalformedPodConfigurations(t *testing.T) {
	tests := []struct {
		name            string
		namespace       *corev1.Namespace
		pod             *corev1.Pod
		enforceLevel    string
		expectViolation bool
		expectError     bool
		description     string
	}{
		{
			name: "pod with malformed SCC annotation",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-ns"},
			},
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "malformed-scc-pod",
					Namespace: "test-ns",
					Annotations: map[string]string{
						securityv1.ValidatedSCCSubjectTypeAnnotation: "invalid-type-!@#",
					},
				},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: &[]bool{false}[0],
					},
				},
			},
			enforceLevel:    "restricted",
			expectViolation: false, // Invalid annotation should be treated as service account
			expectError:     false,
			description:     "should treat malformed SCC annotation as service account",
		},
		{
			name: "pod with empty SCC annotation",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-ns"},
			},
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "empty-scc-pod",
					Namespace: "test-ns",
					Annotations: map[string]string{
						securityv1.ValidatedSCCSubjectTypeAnnotation: "",
					},
				},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: &[]bool{false}[0],
					},
				},
			},
			enforceLevel:    "restricted",
			expectViolation: false, // Empty annotation should be treated as service account
			expectError:     false,
			description:     "should treat empty SCC annotation as service account",
		},
		{
			name: "pod with whitespace-only SCC annotation",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-ns"},
			},
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "whitespace-scc-pod",
					Namespace: "test-ns",
					Annotations: map[string]string{
						securityv1.ValidatedSCCSubjectTypeAnnotation: "   \t\n   ",
					},
				},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: &[]bool{false}[0],
					},
				},
			},
			enforceLevel:    "restricted",
			expectViolation: false, // Whitespace should be treated as service account
			expectError:     false,
			description:     "should treat whitespace-only SCC annotation as service account",
		},
		{
			name: "pod with unicode characters in SCC annotation",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-ns"},
			},
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "unicode-scc-pod",
					Namespace: "test-ns",
					Annotations: map[string]string{
						securityv1.ValidatedSCCSubjectTypeAnnotation: "пользователь", // Russian "user"
					},
				},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: &[]bool{false}[0],
					},
				},
			},
			enforceLevel:    "restricted",
			expectViolation: false, // Non-English should be treated as service account
			expectError:     false,
			description:     "should treat unicode SCC annotation as service account",
		},
		{
			name: "pod with case variation in SCC annotation",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-ns"},
			},
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "case-scc-pod",
					Namespace: "test-ns",
					Annotations: map[string]string{
						securityv1.ValidatedSCCSubjectTypeAnnotation: "User", // Capital U
					},
				},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: &[]bool{false}[0],
					},
				},
			},
			enforceLevel:    "restricted",
			expectViolation: false, // Case sensitive, should be treated as service account
			expectError:     false,
			description:     "should treat case-different SCC annotation as service account",
		},
		{
			name: "pod with multiple SCC-like annotations",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "test-ns"},
			},
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "multi-scc-pod",
					Namespace: "test-ns",
					Annotations: map[string]string{
						securityv1.ValidatedSCCSubjectTypeAnnotation: "user",
						"security.openshift.io/scc.validated-subject-type-alt": "service-account", // Similar but different
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
			enforceLevel:    "restricted",
			expectViolation: true, // Should use the correct annotation key and find user violation
			expectError:     false,
			description:     "should use correct annotation key and ignore similar ones",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := fake.NewSimpleClientset()
			
			if tc.pod != nil {
				_, err := fakeClient.CoreV1().Pods(tc.namespace.Name).Create(context.Background(), tc.pod, metav1.CreateOptions{})
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

			violating, err := controller.isUserViolation(context.Background(), tc.namespace, tc.enforceLevel)

			if (err != nil) != tc.expectError {
				t.Errorf("isUserViolation() error = %v, expectError %v (%s)", err, tc.expectError, tc.description)
				return
			}

			if violating != tc.expectViolation {
				t.Errorf("isUserViolation() violating = %v, expectViolation %v (%s)", violating, tc.expectViolation, tc.description)
			}
		})
	}
}

func TestExtremeScenarios(t *testing.T) {
	tests := []struct {
		name        string
		setupTest   func() (*PodSecurityReadinessController, *corev1.Namespace, string)
		expectError bool
		description string
	}{
		{
			name: "namespace with thousands of pods",
			setupTest: func() (*PodSecurityReadinessController, *corev1.Namespace, string) {
				fakeClient := fake.NewSimpleClientset()
				
				ns := &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{Name: "large-ns"},
				}
				
				// Create many pods to test performance and memory usage
				for i := 0; i < 1000; i++ {
					pod := &corev1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name:      fmt.Sprintf("pod-%d", i),
							Namespace: "large-ns",
						},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: "container", Image: "image"},
							},
						},
					}
					fakeClient.CoreV1().Pods("large-ns").Create(context.Background(), pod, metav1.CreateOptions{})
				}

				psaEvaluator, _ := policy.NewEvaluator(policy.DefaultChecks())
				controller := &PodSecurityReadinessController{
					kubeClient:   fakeClient,
					psaEvaluator: psaEvaluator,
				}
				
				return controller, ns, "restricted"
			},
			expectError: false,
			description: "should handle namespaces with many pods",
		},
		{
			name: "namespace with pods containing very long names",
			setupTest: func() (*PodSecurityReadinessController, *corev1.Namespace, string) {
				fakeClient := fake.NewSimpleClientset()
				
				ns := &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{Name: "long-names-ns"},
				}
				
				// Create pod with maximum allowed name length
				longName := string(make([]byte, 253)) // Max K8s name length
				for i := range longName {
					longName = longName[:i] + "a" + longName[i+1:]
				}
				
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      longName,
						Namespace: "long-names-ns",
						Annotations: map[string]string{
							securityv1.ValidatedSCCSubjectTypeAnnotation: "user",
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "container", Image: "image"},
						},
					},
				}
				fakeClient.CoreV1().Pods("long-names-ns").Create(context.Background(), pod, metav1.CreateOptions{})

				psaEvaluator, _ := policy.NewEvaluator(policy.DefaultChecks())
				controller := &PodSecurityReadinessController{
					kubeClient:   fakeClient,
					psaEvaluator: psaEvaluator,
				}
				
				return controller, ns, "restricted"
			},
			expectError: false,
			description: "should handle pods with very long names",
		},
		{
			name: "namespace with deeply nested security contexts",
			setupTest: func() (*PodSecurityReadinessController, *corev1.Namespace, string) {
				fakeClient := fake.NewSimpleClientset()
				
				ns := &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{Name: "nested-context-ns"},
				}
				
				// Create pod with complex nested security context
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "nested-pod",
						Namespace: "nested-context-ns",
						Annotations: map[string]string{
							securityv1.ValidatedSCCSubjectTypeAnnotation: "user",
						},
					},
					Spec: corev1.PodSpec{
						SecurityContext: &corev1.PodSecurityContext{
							RunAsNonRoot:     &[]bool{true}[0],
							RunAsUser:        &[]int64{1000}[0],
							RunAsGroup:       &[]int64{1000}[0],
							FSGroup:          &[]int64{1000}[0],
							SeccompProfile:   &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
							SELinuxOptions:   &corev1.SELinuxOptions{User: "system_u", Role: "system_r", Type: "container_t", Level: "s0"},
							WindowsOptions:   &corev1.WindowsSecurityContextOptions{},
						},
						Containers: []corev1.Container{
							{
								Name:  "container",
								Image: "image",
								SecurityContext: &corev1.SecurityContext{
									AllowPrivilegeEscalation: &[]bool{false}[0],
									ReadOnlyRootFilesystem:   &[]bool{true}[0],
									RunAsNonRoot:             &[]bool{true}[0],
									RunAsUser:                &[]int64{1001}[0],
									RunAsGroup:               &[]int64{1001}[0],
									Capabilities: &corev1.Capabilities{
										Drop: []corev1.Capability{"ALL"},
										Add:  []corev1.Capability{"NET_BIND_SERVICE"},
									},
									SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
									SELinuxOptions: &corev1.SELinuxOptions{User: "system_u", Role: "system_r", Type: "container_t", Level: "s0:c0,c1"},
								},
							},
						},
					},
				}
				fakeClient.CoreV1().Pods("nested-context-ns").Create(context.Background(), pod, metav1.CreateOptions{})

				psaEvaluator, _ := policy.NewEvaluator(policy.DefaultChecks())
				controller := &PodSecurityReadinessController{
					kubeClient:   fakeClient,
					psaEvaluator: psaEvaluator,
				}
				
				return controller, ns, "restricted"
			},
			expectError: false,
			description: "should handle pods with complex security contexts",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			controller, namespace, enforceLevel := tc.setupTest()
			
			violating, err := controller.isUserViolation(context.Background(), namespace, enforceLevel)
			
			if (err != nil) != tc.expectError {
				t.Errorf("isUserViolation() error = %v, expectError %v (%s)", err, tc.expectError, tc.description)
			}
			
			// For extreme scenarios, we mainly care that they don't crash
			// The specific violation result is less important than stability
			_ = violating
		})
	}
}

func TestBoundaryConditions(t *testing.T) {
	tests := []struct {
		name             string
		namespace        *corev1.Namespace
		enforceLevel     string
		expectViolation  bool
		expectError      bool
		description      string
	}{
		{
			name: "enforce level at exact PSA boundary - baseline to restricted",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "boundary-ns"},
			},
			enforceLevel:    "restricted",
			expectViolation: false,
			expectError:     false,
			description:     "should handle PSA level boundaries correctly",
		},
		{
			name: "PSA level string with trailing newline",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "newline-ns"},
			},
			enforceLevel:    "restricted\n",
			expectViolation: false,
			expectError:     true, // Should fail parsing
			description:     "should reject PSA levels with trailing whitespace",
		},
		{
			name: "PSA level with embedded null byte",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "null-ns"},
			},
			enforceLevel:    "restricted\x00",
			expectViolation: false,
			expectError:     true, // Should fail parsing
			description:     "should reject PSA levels with null bytes",
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

			violating, err := controller.isUserViolation(context.Background(), tc.namespace, tc.enforceLevel)

			if (err != nil) != tc.expectError {
				t.Errorf("isUserViolation() error = %v, expectError %v (%s)", err, tc.expectError, tc.description)
				return
			}

			if !tc.expectError && violating != tc.expectViolation {
				t.Errorf("isUserViolation() violating = %v, expectViolation %v (%s)", violating, tc.expectViolation, tc.description)
			}
		})
	}
}
