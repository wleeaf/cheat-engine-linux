#include "platform/vulkan_overlay_injector.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace ce {
namespace {

std::string jsonEscape(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 8);
    for (char c : value) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out.push_back(c); break;
        }
    }
    return out;
}

std::string appendLayerName(const std::string& existing, const std::string& layerName) {
    if (existing.empty())
        return layerName;

    std::stringstream ss(existing);
    std::string item;
    while (std::getline(ss, item, ':')) {
        if (item == layerName)
            return existing;
    }
    return existing + ":" + layerName;
}

} // namespace

std::string defaultVulkanOverlayLayerName() {
    return "VK_LAYER_CE_linux_overlay";
}

std::string makeVulkanOverlayManifest(
    const std::string& layerLibraryPath,
    const std::string& layerName) {
    std::ostringstream out;
    out <<
        "{\n"
        "  \"file_format_version\": \"1.2.0\",\n"
        "  \"layer\": {\n"
        "    \"name\": \"" << jsonEscape(layerName) << "\",\n"
        "    \"type\": \"GLOBAL\",\n"
        "    \"library_path\": \"" << jsonEscape(layerLibraryPath) << "\",\n"
        "    \"api_version\": \"1.3.0\",\n"
        "    \"implementation_version\": \"1\",\n"
        "    \"description\": \"Cheat Engine Linux Vulkan overlay injection layer\"\n"
        "  }\n"
        "}\n";
    return out.str();
}

bool writeVulkanOverlayManifest(
    const std::string& manifestPath,
    const std::string& layerLibraryPath,
    std::string& error,
    const std::string& layerName) {
    error.clear();

    try {
        auto parent = std::filesystem::path(manifestPath).parent_path();
        if (!parent.empty())
            std::filesystem::create_directories(parent);
    } catch (const std::exception& ex) {
        error = ex.what();
        return false;
    }

    std::ofstream file(manifestPath, std::ios::binary);
    if (!file) {
        error = "failed to open Vulkan layer manifest for writing: " + manifestPath;
        return false;
    }

    file << makeVulkanOverlayManifest(layerLibraryPath, layerName);
    if (!file) {
        error = "failed to write Vulkan layer manifest: " + manifestPath;
        return false;
    }
    return true;
}

VulkanOverlayEnvironment buildVulkanOverlayEnvironment(
    const std::string& manifestDirectory,
    const std::string& layerLibraryPath,
    const std::string& existingInstanceLayers,
    const std::string& layerName) {
    auto manifestPath = (std::filesystem::path(manifestDirectory) /
        (layerName + ".json")).string();

    VulkanOverlayEnvironment env;
    env.layerName = layerName;
    env.manifestPath = manifestPath;
    env.variables.push_back({"VK_LAYER_PATH", manifestDirectory});
    env.variables.push_back({"VK_INSTANCE_LAYERS", appendLayerName(existingInstanceLayers, layerName)});
    env.variables.push_back({"CE_VULKAN_OVERLAY", "1"});
    env.variables.push_back({"CE_VULKAN_OVERLAY_LIBRARY", layerLibraryPath});
    return env;
}

} // namespace ce
