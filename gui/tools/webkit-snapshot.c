// Render a URL in WebKitGTK and save a PNG snapshot once loaded.
#include <gtk/gtk.h>
#include <webkit2/webkit2.h>

static const char *out_path;
static GtkWidget *window, *webview;

static void on_snapshot(GObject *obj, GAsyncResult *res, gpointer data) {
    GError *err = NULL;
    cairo_surface_t *surf =
        webkit_web_view_get_snapshot_finish(WEBKIT_WEB_VIEW(obj), res, &err);
    if (surf) {
        cairo_surface_write_to_png(surf, out_path);
        cairo_surface_destroy(surf);
        g_print("saved %s\n", out_path);
    } else {
        g_printerr("snapshot failed: %s\n", err ? err->message : "?");
    }
    gtk_main_quit();
}

static gboolean take_shot(gpointer data) {
    webkit_web_view_get_snapshot(WEBKIT_WEB_VIEW(webview),
                                 WEBKIT_SNAPSHOT_REGION_VISIBLE,
                                 WEBKIT_SNAPSHOT_OPTIONS_NONE, NULL,
                                 on_snapshot, NULL);
    return G_SOURCE_REMOVE;
}

static void on_load(WebKitWebView *wv, WebKitLoadEvent ev, gpointer data) {
    if (ev == WEBKIT_LOAD_FINISHED)
        g_timeout_add(3500, take_shot, NULL); // let React render + fonts settle
}

int main(int argc, char **argv) {
    const char *url = argc > 1 ? argv[1] : "http://localhost:1420/";
    out_path = argc > 2 ? argv[2] : "/tmp/rustypods-gui.png";
    gtk_init(&argc, &argv);
    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_default_size(GTK_WINDOW(window), 1100, 720);
    webview = webkit_web_view_new();
    gtk_container_add(GTK_CONTAINER(window), webview);
    g_signal_connect(webview, "load-changed", G_CALLBACK(on_load), NULL);
    gtk_widget_show_all(window);
    webkit_web_view_load_uri(WEBKIT_WEB_VIEW(webview), url);
    g_timeout_add(20000, (GSourceFunc)gtk_main_quit, NULL); // safety
    gtk_main();
    return 0;
}
