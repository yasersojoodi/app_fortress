# Rules applied to the app that uses App Fortress (R8 of the app build).

# Flutter registers the plugin by its class name
-keep class com.app.fortress.AppFortressPlugin { *; }

# JNI functions are looked up by class / method name
-keepclasseswithmembernames class * {
    native <methods>;
}

# Play Integrity API
-keep class com.google.android.play.core.integrity.** { *; }
-dontwarn com.google.android.play.core.**
