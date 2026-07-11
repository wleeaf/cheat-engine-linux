#pragma once
/// Vulkan explicit-layer injection helpers for launching games with the CE overlay layer enabled.

#include <string>
#include <utility>
#include <vector>

namespace ce {

struct VulkanOverlayEnvironment {
    std::string layerName;
    std::string manifestPath;
    std::vector<std::pair<std::string, std::string>> variables;
};

std::string defaultVulkanOverlayLayerName();
std::string makeVulkanOverlayManifest(
    const std::string& layerLibraryPath,
    const std::string& layerName = defaultVulkanOverlayLayerName());
bool writeVulkanOverlayManifest(
    const std::string& manifestPath,
    const std::string& layerLibraryPath,
    std::string& error,
    const std::string& layerName = defaultVulkanOverlayLayerName());
VulkanOverlayEnvironment buildVulkanOverlayEnvironment(
    const std::string& manifestDirectory,
    const std::string& layerLibraryPath,
    const std::string& existingInstanceLayers = {},
    const std::string& layerName = defaultVulkanOverlayLayerName());

} // namespace ce
