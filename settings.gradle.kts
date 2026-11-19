pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "FirewallDNS-Engine"
include(":engine-core", ":dns-engine", ":threat-engine", ":engine-monitor", ":engine-runtime", ":android-adapter")
