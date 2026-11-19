pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

rootProject.name = "FirewallDNS-Engine"
include(":engine-core", ":dns-engine", ":threat-engine", ":engine-monitor", ":engine-runtime", ":android-adapter")
