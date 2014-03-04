package net.hetimatan.net.http;

import net.hetimatan.io.file.KyoroFile;
import net.hetimatan.util.http.HttpRequest;

public interface HttpServerListener {
	public KyoroFile onRequest(HttpRequest req);
}
