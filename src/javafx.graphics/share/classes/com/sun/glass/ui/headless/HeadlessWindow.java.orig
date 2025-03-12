package com.sun.glass.ui.headless;

import com.sun.glass.events.MouseEvent;
import com.sun.glass.events.ViewEvent;
import com.sun.glass.events.WindowEvent;
import com.sun.glass.ui.Application;
import com.sun.glass.ui.Cursor;
import com.sun.glass.ui.Pixels;
import com.sun.glass.ui.Screen;
import com.sun.glass.ui.View;
import com.sun.glass.ui.Window;


final class HeadlessWindow extends Window {


    private static final int STATE_NORMAL = 0;
    private static final int STATE_MINIMIZED = 1;
    private static final int STATE_MAXIMIZED = 2;
    private static final int STATE_FULLSCREEN = 3;

    private int id;
    private int state;
    private int cachedX, cachedY, cachedW, cachedH;
    private int minW, minH;
    private int maxW = -1;
    private int maxH = -1;

    HeadlessWindow(Window owner, Screen screen, int styleMask) {
        super(owner, screen, styleMask);
    }

    @Override
    protected void _toFront(long ptr) {
    }

    @Override
    protected void _toBack(long ptr) {

    }

    /**
     *
     * w/h is the total window width/height including all its
     * decorations (e.g. title bar). cw/ch is the "client", or
     * interior width/height. Negative values for w/h/cw/ch are
     * treated as "not set". For example: setBounds(x, y, xSet,
     * ySet, 800, 600, -1, -1) will make the window 800x600 pixels.
     * The client area available for drawing will be smaller, e.g.
     * 792x580 - it depends on the window decorations on different
     * platforms. setBounds(x, y, xSet, ySet, -1, -1, 800, 600) will
     * make the window client size to be 800x600 pixels. The area
     * for drawing (FX scene size) will be exactly 800x600, but the
     * total window size including decorations will be slightly
     * bigger. For undecorated windows w/h and cw/ch are obviously
     * the same.
     *
     * As this is a void function the native code should trigger an
     * event to notify the system on actual change
     *
     */
    @Override
    protected void _setBounds(long nativeWindowPointer,
                              int x, int y, boolean xSet, boolean ySet,
                              int w, int h, int cw, int ch,
                              float xGravity, float yGravity) {
        int width;
        int height;

        if (w > 0) {
            //window width surpass window content width (cw)
            width = w;
        } else if (cw > 0) {
            //content width changed
            width = cw;
        } else {
            //no explicit request to change width, get default
            width = getWidth();
        }

        if (h > 0) {
            //window height surpass window content height(ch)
            height = h;
        } else if (ch > 0) {
            //content height changed
            height = ch;
        } else {
            //no explicit request to change height, get default
            height = getHeight();
        }
        if (!xSet) {
            x = getX();
        }
        if (!ySet) {
            y = getY();
        }
        if (maxW >= 0) {
            width = Math.min(width, maxW);
        }
        if (maxH >= 0) {
            height = Math.min(height, maxH);
        }
        width = Math.max(width, minW);
        height = Math.max(height, minH);

        notifyResizeAndMove(x, y, width, height);
    }

    private void notifyResizeAndMove(int x, int y, int width, int height) {
        HeadlessView view = (HeadlessView)getView();
        if (getWidth() != width || getHeight() != height) {
            notifyResize(WindowEvent.RESIZE, width, height);
            if (view != null) {
                view.notifyResize(width, height);
            }
        }
        if (getX() != x || getY() != y) {
            notifyMove(x, y);
        }

    }

    //creates the native window
    @Override
    protected long _createWindow(long NativeWindow, long NativeScreen,
                                 int mask) {
        return 1;
    }

    @Override
    protected boolean _close(long nativeWindowPointer) {
        return true;
    }

    @Override
    protected boolean _setView(long nativeWindowPointer, View view) {
        return true;
    }

    // empty - not needed by this implementation
    @Override
    protected void _updateViewSize(long ptr) {}

    /**
     * Returns the handle used to create a rendering context in Prism
     */
    @Override
    public long getNativeWindow() {
        return id;
    }

    @Override
    protected boolean _setMenubar(long ptr, long menubarPtr) {
        return true;
    }

    @Override
    protected boolean _minimize(long nativeWindowPointer, boolean minimize) {
        int x = getX();
        int y = getY();
        int width = getWidth();
        int height = getHeight();
        if (minimize && !(state == STATE_MINIMIZED)) {
            state = STATE_MINIMIZED;
            cachedX = x;
            cachedY = y;
            cachedW = width;
            cachedH = height;
            // remove the window from the list of visible windows in the
            // superclass
            remove(this);
            notifyResize(WindowEvent.MINIMIZE, width, height);

        } else if (!minimize && state == STATE_MINIMIZED) {
            state = STATE_NORMAL;
            x = cachedX;
            y = cachedY;
            width = cachedW;
            height = cachedH;
            // this call will add the window back into the visible list of
            // windows in the superclass
            add(this);
            notifyResize(WindowEvent.RESTORE, width, height);
        }
        return true;
    }

    @Override
    protected boolean _maximize(long nativeWindowPointer, boolean maximize,
                                boolean wasMaximized) {
        return true;
    }

    @Override
    protected void notifyMoveToAnotherScreen(Screen screen) {
        super.notifyMoveToAnotherScreen(screen);
    }

    void setFullScreen(boolean fullscreen) {
    }

    private float cachedAlpha = 1;
    @Override
    protected boolean _setVisible(long ptr, boolean visible) {
        if (visible) {
            setAlpha(cachedAlpha);
        } else {
            cachedAlpha = getAlpha();
            setAlpha(0);
        }

        return true;
    }

    @Override
    protected boolean _setResizable(long ptr, boolean resizable){
        return true;
    }

    @Override
    protected boolean _requestFocus(long ptr, int event) {
        return true;
    }

    @Override
    protected void _setFocusable(long ptr, boolean isFocusable){}

    @Override
    protected boolean _setTitle(long ptr, String title) {
        return true;
    }

    @Override
    protected void _setLevel(long ptr, int level) {}

    @Override
    protected void _setAlpha(long ptr, float alpha) {}

    @Override
    protected boolean _setBackground(long ptr, float r, float g, float b) {
        return true;
    }

    @Override
    protected void _setEnabled(long ptr, boolean enabled){
    }

    @Override
    protected boolean _setMinimumSize(long ptr, int width, int height) {
        return true;
    }

    @Override
    protected boolean _setMaximumSize(long ptr, int width, int height) {
        maxW = width;
        maxH = height;
        return true;
    }

    @Override
    protected void _setIcon(long ptr, Pixels pixels){}

    @Override
    protected boolean _grabFocus(long ptr) {
        return true;
    }

    @Override
    protected void _ungrabFocus(long ptr) {
    }

    /**
     * The functions below are used when the platform support modality natively.
     * Currently only GTK is using it. This functionality is disabled by
     * default. In order to enable it this class need to override Window::
     * supportsPlatformModality() to return true.
     *
     */
    @Override
    protected void _enterModal(long ptr) {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void _enterModalWithWindow(long dialog, long window) {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void _exitModal(long ptr) {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void notifyClose() {
        super.notifyClose();
        close();
    }

    @Override
    protected void notifyDestroy() {
        super.notifyDestroy();
    }

    @Override
    protected void notifyFocus(int event) {
        super.notifyFocus(event);
    }

    protected void _notifyFocusUngrab() {
        notifyFocusUngrab();
    }

    void _notifyFocusDisabled() {
        notifyFocusDisabled();
    }

    //**************************************************************

    @Override protected void _setCursor(long ptr, Cursor cursor) {
    }

    @Override
    protected void _requestInput(long ptr, String text, int type, double width, double height,
                                 double Mxx, double Mxy, double Mxz, double Mxt,
                                 double Myx, double Myy, double Myz, double Myt,
                                 double Mzx, double Mzy, double Mzz, double Mzt) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    protected void _releaseInput(long ptr) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

}
