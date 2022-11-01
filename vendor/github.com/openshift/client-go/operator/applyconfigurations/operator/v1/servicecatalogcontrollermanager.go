// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

import (
	apioperatorv1 "github.com/openshift/api/operator/v1"
	internal "github.com/openshift/client-go/operator/applyconfigurations/internal"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	managedfields "k8s.io/apimachinery/pkg/util/managedfields"
	v1 "k8s.io/client-go/applyconfigurations/meta/v1"
)

// ServiceCatalogControllerManagerApplyConfiguration represents an declarative configuration of the ServiceCatalogControllerManager type for use
// with apply.
type ServiceCatalogControllerManagerApplyConfiguration struct {
	v1.TypeMetaApplyConfiguration    `json:",inline"`
	*v1.ObjectMetaApplyConfiguration `json:"metadata,omitempty"`
	Spec                             *ServiceCatalogControllerManagerSpecApplyConfiguration   `json:"spec,omitempty"`
	Status                           *ServiceCatalogControllerManagerStatusApplyConfiguration `json:"status,omitempty"`
}

// ServiceCatalogControllerManager constructs an declarative configuration of the ServiceCatalogControllerManager type for use with
// apply.
func ServiceCatalogControllerManager(name string) *ServiceCatalogControllerManagerApplyConfiguration {
	b := &ServiceCatalogControllerManagerApplyConfiguration{}
	b.WithName(name)
	b.WithKind("ServiceCatalogControllerManager")
	b.WithAPIVersion("operator.openshift.io/v1")
	return b
}

// ExtractServiceCatalogControllerManager extracts the applied configuration owned by fieldManager from
// serviceCatalogControllerManager. If no managedFields are found in serviceCatalogControllerManager for fieldManager, a
// ServiceCatalogControllerManagerApplyConfiguration is returned with only the Name, Namespace (if applicable),
// APIVersion and Kind populated. It is possible that no managed fields were found for because other
// field managers have taken ownership of all the fields previously owned by fieldManager, or because
// the fieldManager never owned fields any fields.
// serviceCatalogControllerManager must be a unmodified ServiceCatalogControllerManager API object that was retrieved from the Kubernetes API.
// ExtractServiceCatalogControllerManager provides a way to perform a extract/modify-in-place/apply workflow.
// Note that an extracted apply configuration will contain fewer fields than what the fieldManager previously
// applied if another fieldManager has updated or force applied any of the previously applied fields.
// Experimental!
func ExtractServiceCatalogControllerManager(serviceCatalogControllerManager *apioperatorv1.ServiceCatalogControllerManager, fieldManager string) (*ServiceCatalogControllerManagerApplyConfiguration, error) {
	return extractServiceCatalogControllerManager(serviceCatalogControllerManager, fieldManager, "")
}

// ExtractServiceCatalogControllerManagerStatus is the same as ExtractServiceCatalogControllerManager except
// that it extracts the status subresource applied configuration.
// Experimental!
func ExtractServiceCatalogControllerManagerStatus(serviceCatalogControllerManager *apioperatorv1.ServiceCatalogControllerManager, fieldManager string) (*ServiceCatalogControllerManagerApplyConfiguration, error) {
	return extractServiceCatalogControllerManager(serviceCatalogControllerManager, fieldManager, "status")
}

func extractServiceCatalogControllerManager(serviceCatalogControllerManager *apioperatorv1.ServiceCatalogControllerManager, fieldManager string, subresource string) (*ServiceCatalogControllerManagerApplyConfiguration, error) {
	b := &ServiceCatalogControllerManagerApplyConfiguration{}
	err := managedfields.ExtractInto(serviceCatalogControllerManager, internal.Parser().Type("com.github.openshift.api.operator.v1.ServiceCatalogControllerManager"), fieldManager, b, subresource)
	if err != nil {
		return nil, err
	}
	b.WithName(serviceCatalogControllerManager.Name)

	b.WithKind("ServiceCatalogControllerManager")
	b.WithAPIVersion("operator.openshift.io/v1")
	return b, nil
}

// WithKind sets the Kind field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Kind field is set to the value of the last call.
func (b *ServiceCatalogControllerManagerApplyConfiguration) WithKind(value string) *ServiceCatalogControllerManagerApplyConfiguration {
	b.Kind = &value
	return b
}

// WithAPIVersion sets the APIVersion field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the APIVersion field is set to the value of the last call.
func (b *ServiceCatalogControllerManagerApplyConfiguration) WithAPIVersion(value string) *ServiceCatalogControllerManagerApplyConfiguration {
	b.APIVersion = &value
	return b
}

// WithName sets the Name field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Name field is set to the value of the last call.
func (b *ServiceCatalogControllerManagerApplyConfiguration) WithName(value string) *ServiceCatalogControllerManagerApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.Name = &value
	return b
}

// WithGenerateName sets the GenerateName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the GenerateName field is set to the value of the last call.
func (b *ServiceCatalogControllerManagerApplyConfiguration) WithGenerateName(value string) *ServiceCatalogControllerManagerApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.GenerateName = &value
	return b
}

// WithNamespace sets the Namespace field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Namespace field is set to the value of the last call.
func (b *ServiceCatalogControllerManagerApplyConfiguration) WithNamespace(value string) *ServiceCatalogControllerManagerApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.Namespace = &value
	return b
}

// WithUID sets the UID field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the UID field is set to the value of the last call.
func (b *ServiceCatalogControllerManagerApplyConfiguration) WithUID(value types.UID) *ServiceCatalogControllerManagerApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.UID = &value
	return b
}

// WithResourceVersion sets the ResourceVersion field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ResourceVersion field is set to the value of the last call.
func (b *ServiceCatalogControllerManagerApplyConfiguration) WithResourceVersion(value string) *ServiceCatalogControllerManagerApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.ResourceVersion = &value
	return b
}

// WithGeneration sets the Generation field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Generation field is set to the value of the last call.
func (b *ServiceCatalogControllerManagerApplyConfiguration) WithGeneration(value int64) *ServiceCatalogControllerManagerApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.Generation = &value
	return b
}

// WithCreationTimestamp sets the CreationTimestamp field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the CreationTimestamp field is set to the value of the last call.
func (b *ServiceCatalogControllerManagerApplyConfiguration) WithCreationTimestamp(value metav1.Time) *ServiceCatalogControllerManagerApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.CreationTimestamp = &value
	return b
}

// WithDeletionTimestamp sets the DeletionTimestamp field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the DeletionTimestamp field is set to the value of the last call.
func (b *ServiceCatalogControllerManagerApplyConfiguration) WithDeletionTimestamp(value metav1.Time) *ServiceCatalogControllerManagerApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.DeletionTimestamp = &value
	return b
}

// WithDeletionGracePeriodSeconds sets the DeletionGracePeriodSeconds field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the DeletionGracePeriodSeconds field is set to the value of the last call.
func (b *ServiceCatalogControllerManagerApplyConfiguration) WithDeletionGracePeriodSeconds(value int64) *ServiceCatalogControllerManagerApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.DeletionGracePeriodSeconds = &value
	return b
}

// WithLabels puts the entries into the Labels field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, the entries provided by each call will be put on the Labels field,
// overwriting an existing map entries in Labels field with the same key.
func (b *ServiceCatalogControllerManagerApplyConfiguration) WithLabels(entries map[string]string) *ServiceCatalogControllerManagerApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	if b.Labels == nil && len(entries) > 0 {
		b.Labels = make(map[string]string, len(entries))
	}
	for k, v := range entries {
		b.Labels[k] = v
	}
	return b
}

// WithAnnotations puts the entries into the Annotations field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, the entries provided by each call will be put on the Annotations field,
// overwriting an existing map entries in Annotations field with the same key.
func (b *ServiceCatalogControllerManagerApplyConfiguration) WithAnnotations(entries map[string]string) *ServiceCatalogControllerManagerApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	if b.Annotations == nil && len(entries) > 0 {
		b.Annotations = make(map[string]string, len(entries))
	}
	for k, v := range entries {
		b.Annotations[k] = v
	}
	return b
}

// WithOwnerReferences adds the given value to the OwnerReferences field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the OwnerReferences field.
func (b *ServiceCatalogControllerManagerApplyConfiguration) WithOwnerReferences(values ...*v1.OwnerReferenceApplyConfiguration) *ServiceCatalogControllerManagerApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithOwnerReferences")
		}
		b.OwnerReferences = append(b.OwnerReferences, *values[i])
	}
	return b
}

// WithFinalizers adds the given value to the Finalizers field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Finalizers field.
func (b *ServiceCatalogControllerManagerApplyConfiguration) WithFinalizers(values ...string) *ServiceCatalogControllerManagerApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	for i := range values {
		b.Finalizers = append(b.Finalizers, values[i])
	}
	return b
}

func (b *ServiceCatalogControllerManagerApplyConfiguration) ensureObjectMetaApplyConfigurationExists() {
	if b.ObjectMetaApplyConfiguration == nil {
		b.ObjectMetaApplyConfiguration = &v1.ObjectMetaApplyConfiguration{}
	}
}

// WithSpec sets the Spec field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Spec field is set to the value of the last call.
func (b *ServiceCatalogControllerManagerApplyConfiguration) WithSpec(value *ServiceCatalogControllerManagerSpecApplyConfiguration) *ServiceCatalogControllerManagerApplyConfiguration {
	b.Spec = value
	return b
}

// WithStatus sets the Status field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Status field is set to the value of the last call.
func (b *ServiceCatalogControllerManagerApplyConfiguration) WithStatus(value *ServiceCatalogControllerManagerStatusApplyConfiguration) *ServiceCatalogControllerManagerApplyConfiguration {
	b.Status = value
	return b
}