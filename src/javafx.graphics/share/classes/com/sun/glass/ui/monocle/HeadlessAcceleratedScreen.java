/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.sun.glass.ui.monocle;

/**
 *
 * @author johan
 */
public class HeadlessAcceleratedScreen extends AcceleratedScreen {

    public HeadlessAcceleratedScreen(int[] attributes) throws GLException {
        System.err.println("[JVDBG] created HeadlessAcceleratedScreen");
    }

    boolean initPlatformLibraries() throws UnsatisfiedLinkError {
        System.err.println("[JVDBG] headless, don't need to import more libs");
        return true;
    }

    public void enableRendering(boolean flag) {
        System.err.println("[JVDBG] enableRendering");
    }
}
