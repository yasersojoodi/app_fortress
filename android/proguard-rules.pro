# App Fortress ProGuard Rules - Production Security

# Keep plugin class and all its methods
-keep class com.app.fortress.AppFortressPlugin { *; }

# Keep native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Flutter plugin keep rules
-keep class io.flutter.** { *; }
-keep class io.flutter.plugins.** { *; }

# Play Integrity API
-keep class com.google.android.play.core.integrity.** { *; }

# Kotlin coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-keepclassmembers class kotlinx.coroutines.** {
    volatile <fields>;
}

# Remove all logging in release builds
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
}

# Security: Obfuscate class names
-repackageclasses 'a'
-allowaccessmodification
-useuniqueclassmembernames

# Security: Optimize for smaller size
-optimizations !code/simplification/arithmetic,!code/simplification/cast,!field/*,!class/merging/*

# Security: Remove unused code
-dontwarn kotlin.**
-dontwarn kotlinx.**
