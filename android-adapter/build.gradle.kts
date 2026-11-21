plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.firewalldns.engine.android"
    compileSdk = 36

    defaultConfig {
        minSdk = 24
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    kotlinOptions {
        jvmTarget = "21"
    }
}

dependencies {
    api(project(":dns-engine"))
    api(project(":engine-runtime"))
    testImplementation("junit:junit:4.13.2")
}

 
// Build the JNI shared library for the supported Samsung A34 ARM64 target.
val cargoBuildArm64 by tasks.registering(Exec::class) {
    val rustRoot = rootProject.layout.projectDirectory.dir("rust-core")
    val jniLibs = layout.projectDirectory.dir("src/main/jniLibs")
    val output = jniLibs.file("arm64-v8a/libfirewalldns_native.so")
    workingDir(rustRoot)
    inputs.files(fileTree(rustRoot) { exclude("target/**") })
    outputs.file(output)
    doFirst { jniLibs.asFile.mkdirs() }
    commandLine(
        "cargo", "ndk",
        "-t", "arm64-v8a",
        "-o", jniLibs.asFile.absolutePath,
        "build", "--release",
    )
}

tasks.named("preBuild").configure {
    dependsOn(cargoBuildArm64)
}
