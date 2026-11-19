plugins {
    kotlin("jvm") version "2.1.20" apply false
    id("com.android.library") version "8.10.1" apply false
    id("org.jetbrains.kotlin.android") version "2.1.20" apply false
}

allprojects {
    group = "com.firewalldns.engine"
    version = "0.1.0"

    repositories {
        mavenCentral()
    }
}
