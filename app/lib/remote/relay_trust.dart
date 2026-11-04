import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/services.dart';

/// 只信任内置的 DSH Relay 自建 CA。
///
/// DSH Go 的所有 HTTP / WebSocket 都走 dart:io 的 HttpClient，
/// 而 HttpClient 遵循全局 HttpOverrides。因此在这里设置一次，
/// 整个 App（含 WebSocket.connect）都会信任这张自签名 CA，
/// 同时不信任任何其他自签名证书。
class RelayHttpOverrides extends HttpOverrides {
  RelayHttpOverrides(this._caPem);

  final Uint8List _caPem;

  @override
  HttpClient createHttpClient(SecurityContext? context) {
    final SecurityContext security;
    try {
      security = SecurityContext(withTrustedRoots: true)
        ..setTrustedCertificatesBytes(_caPem);
    } on TlsException {
      // CA 格式异常时退回系统根证书，不影响其他网络功能。
      return super.createHttpClient(context);
    }
    return super.createHttpClient(security);
  }
}

/// 从 assets 读取 CA 并安装全局 HttpOverrides。
/// 失败时静默跳过（例如未打包 CA 的官方构建）。
Future<void> installRelayTrust() async {
  try {
    final data = await rootBundle.load('assets/tls/dsh-relay-ca.crt');
    HttpOverrides.global = RelayHttpOverrides(data.buffer.asUint8List());
  } catch (_) {
    // 忽略：没有 CA 时保持默认信任链。
  }
}
