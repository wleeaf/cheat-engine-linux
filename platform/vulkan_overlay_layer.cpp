#include <vulkan/vk_layer.h>
#include <vulkan/vulkan.h>

#include <algorithm>
#include <cstring>

namespace {

constexpr const char* kLayerName = "VK_LAYER_CE_linux_overlay";
constexpr const char* kLayerDescription = "Cheat Engine Linux Vulkan overlay injection layer";

VkLayerInstanceCreateInfo* findInstanceLink(const VkInstanceCreateInfo* createInfo) {
    auto* chain = reinterpret_cast<const VkLayerInstanceCreateInfo*>(createInfo->pNext);
    while (chain) {
        if (chain->sType == VK_STRUCTURE_TYPE_LOADER_INSTANCE_CREATE_INFO &&
            chain->function == VK_LAYER_LINK_INFO) {
            return const_cast<VkLayerInstanceCreateInfo*>(chain);
        }
        chain = reinterpret_cast<const VkLayerInstanceCreateInfo*>(chain->pNext);
    }
    return nullptr;
}

VkLayerDeviceCreateInfo* findDeviceLink(const VkDeviceCreateInfo* createInfo) {
    auto* chain = reinterpret_cast<const VkLayerDeviceCreateInfo*>(createInfo->pNext);
    while (chain) {
        if (chain->sType == VK_STRUCTURE_TYPE_LOADER_DEVICE_CREATE_INFO &&
            chain->function == VK_LAYER_LINK_INFO) {
            return const_cast<VkLayerDeviceCreateInfo*>(chain);
        }
        chain = reinterpret_cast<const VkLayerDeviceCreateInfo*>(chain->pNext);
    }
    return nullptr;
}

VkLayerProperties layerProperties() {
    VkLayerProperties props{};
    std::strncpy(props.layerName, kLayerName, VK_MAX_EXTENSION_NAME_SIZE - 1);
    props.specVersion = VK_API_VERSION_1_3;
    props.implementationVersion = 1;
    std::strncpy(props.description, kLayerDescription, VK_MAX_DESCRIPTION_SIZE - 1);
    return props;
}

} // namespace

extern "C" __attribute__((visibility("default"))) VKAPI_ATTR VkResult VKAPI_CALL vkEnumerateInstanceLayerProperties(
    uint32_t* propertyCount,
    VkLayerProperties* properties) {
    if (!propertyCount)
        return VK_ERROR_INITIALIZATION_FAILED;

    if (!properties) {
        *propertyCount = 1;
        return VK_SUCCESS;
    }

    if (*propertyCount == 0)
        return VK_INCOMPLETE;

    properties[0] = layerProperties();
    *propertyCount = 1;
    return VK_SUCCESS;
}

extern "C" __attribute__((visibility("default"))) VKAPI_ATTR VkResult VKAPI_CALL vkEnumerateInstanceExtensionProperties(
    const char*,
    uint32_t* propertyCount,
    VkExtensionProperties*) {
    if (!propertyCount)
        return VK_ERROR_INITIALIZATION_FAILED;
    *propertyCount = 0;
    return VK_SUCCESS;
}

extern "C" __attribute__((visibility("default"))) VKAPI_ATTR VkResult VKAPI_CALL vkCreateInstance(
    const VkInstanceCreateInfo* createInfo,
    const VkAllocationCallbacks* allocator,
    VkInstance* instance) {
    auto* linkInfo = findInstanceLink(createInfo);
    if (!linkInfo || !linkInfo->u.pLayerInfo || !linkInfo->u.pLayerInfo->pfnNextGetInstanceProcAddr)
        return VK_ERROR_INITIALIZATION_FAILED;

    auto nextGetInstanceProcAddr = linkInfo->u.pLayerInfo->pfnNextGetInstanceProcAddr;
    auto nextCreateInstance = reinterpret_cast<PFN_vkCreateInstance>(
        nextGetInstanceProcAddr(nullptr, "vkCreateInstance"));
    if (!nextCreateInstance)
        return VK_ERROR_INITIALIZATION_FAILED;

    linkInfo->u.pLayerInfo = linkInfo->u.pLayerInfo->pNext;
    return nextCreateInstance(createInfo, allocator, instance);
}

extern "C" __attribute__((visibility("default"))) VKAPI_ATTR VkResult VKAPI_CALL vkCreateDevice(
    VkPhysicalDevice physicalDevice,
    const VkDeviceCreateInfo* createInfo,
    const VkAllocationCallbacks* allocator,
    VkDevice* device) {
    auto* linkInfo = findDeviceLink(createInfo);
    if (!linkInfo || !linkInfo->u.pLayerInfo || !linkInfo->u.pLayerInfo->pfnNextGetInstanceProcAddr)
        return VK_ERROR_INITIALIZATION_FAILED;

    auto nextGetInstanceProcAddr = linkInfo->u.pLayerInfo->pfnNextGetInstanceProcAddr;
    auto nextCreateDevice = reinterpret_cast<PFN_vkCreateDevice>(
        nextGetInstanceProcAddr(nullptr, "vkCreateDevice"));
    if (!nextCreateDevice)
        return VK_ERROR_INITIALIZATION_FAILED;

    linkInfo->u.pLayerInfo = linkInfo->u.pLayerInfo->pNext;
    return nextCreateDevice(physicalDevice, createInfo, allocator, device);
}

extern "C" __attribute__((visibility("default"))) VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL vkGetInstanceProcAddr(
    VkInstance,
    const char* name) {
    if (!name)
        return nullptr;
    if (std::strcmp(name, "vkGetInstanceProcAddr") == 0)
        return reinterpret_cast<PFN_vkVoidFunction>(vkGetInstanceProcAddr);
    if (std::strcmp(name, "vkEnumerateInstanceLayerProperties") == 0)
        return reinterpret_cast<PFN_vkVoidFunction>(vkEnumerateInstanceLayerProperties);
    if (std::strcmp(name, "vkEnumerateInstanceExtensionProperties") == 0)
        return reinterpret_cast<PFN_vkVoidFunction>(vkEnumerateInstanceExtensionProperties);
    if (std::strcmp(name, "vkCreateInstance") == 0)
        return reinterpret_cast<PFN_vkVoidFunction>(vkCreateInstance);
    if (std::strcmp(name, "vkCreateDevice") == 0)
        return reinterpret_cast<PFN_vkVoidFunction>(vkCreateDevice);
    return nullptr;
}

extern "C" __attribute__((visibility("default"))) VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL vkGetDeviceProcAddr(
    VkDevice,
    const char* name) {
    if (!name)
        return nullptr;
    if (std::strcmp(name, "vkGetDeviceProcAddr") == 0)
        return reinterpret_cast<PFN_vkVoidFunction>(vkGetDeviceProcAddr);
    return nullptr;
}

extern "C" __attribute__((visibility("default"))) VKAPI_ATTR VkResult VKAPI_CALL vkNegotiateLoaderLayerInterfaceVersion(
    VkNegotiateLayerInterface* version) {
    if (!version || version->sType != LAYER_NEGOTIATE_INTERFACE_STRUCT)
        return VK_ERROR_INITIALIZATION_FAILED;

    version->loaderLayerInterfaceVersion = std::min(
        version->loaderLayerInterfaceVersion,
        static_cast<uint32_t>(CURRENT_LOADER_LAYER_INTERFACE_VERSION));
    version->pfnGetInstanceProcAddr = vkGetInstanceProcAddr;
    version->pfnGetDeviceProcAddr = vkGetDeviceProcAddr;
    version->pfnGetPhysicalDeviceProcAddr = nullptr;
    return VK_SUCCESS;
}
