pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

rootProject.name = "FirewallDNS-Engine"

include(
    ":engine-core",
    ":threat-engine",
    ":engine-monitor",
    ":dns-engine",
    ":engine-runtime",
    ":android-adapter",
    ":app",
)
