plugins {
    kotlin("jvm")
    `java-library`
}

kotlin { jvmToolchain(21) }

dependencies {
    api(project(":engine-core"))
    api(project(":dns-engine"))
    api(project(":threat-engine"))
    api(project(":engine-monitor"))
    testImplementation(kotlin("test-junit5"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.11.4")
}

tasks.test { useJUnitPlatform() }
