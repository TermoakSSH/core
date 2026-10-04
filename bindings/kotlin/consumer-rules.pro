# JNA and the UniFFI bindings use reflection: R8 must not rename them.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class com.termoak.ffi.** { *; }
-dontwarn java.awt.**
