use std::net::SocketAddr;

use axum::Router;

/// Serve an Axum app until the process exits (no graceful shutdown hook).
///
/// Expects [`Router::with_state`](axum::Router::with_state) to have been applied so the router is
/// a [`Router<()>`] (no missing state).
///
/// Uses [`Router::into_make_service_with_connect_info`] so handlers can use
/// <code>[axum::extract::connect_info::ConnectInfo]<[SocketAddr]></code>.
///
/// # Errors
///
/// Returns an error when Axum's accept loop fails (I/O / listener error from
/// [`axum::serve()`]).
///
/// # Examples
///
/// ```rust,no_run
/// use axum::Router;
/// use soliton::{bind_tcp, resolve_listen_addr, serve, ListenAddrDefault};
///
/// # async fn demo() -> anyhow::Result<()> {
/// let addr = resolve_listen_addr(ListenAddrDefault::Loopback { port: 0 })?;
/// let listener = bind_tcp(&addr).await?;
/// serve(listener, Router::new()).await
/// # }
/// ```
pub async fn serve(listener: tokio::net::TcpListener, app: Router<()>) -> anyhow::Result<()> {
    let addr = listener.local_addr().ok();
    tracing::info!(?addr, "soliton serve starting");
    match axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    {
        Ok(()) => {
            tracing::info!(?addr, "soliton serve stopped");
            Ok(())
        }
        Err(err) => {
            tracing::error!(?addr, error = %err, "soliton serve failed");
            Err(err.into())
        }
    }
}

/// Serve with a graceful shutdown future (e.g. ctrl-c).
///
/// # Errors
///
/// Returns an error when Axum's accept loop fails (I/O / listener error from
/// [`axum::serve()`]).
///
/// # Examples
///
/// ```rust,no_run
/// use axum::Router;
/// use soliton::{
///     bind_tcp, resolve_listen_addr, serve_with_graceful_shutdown, ListenAddrDefault,
/// };
/// use tokio::signal;
///
/// # async fn demo() -> anyhow::Result<()> {
/// let addr = resolve_listen_addr(ListenAddrDefault::Loopback { port: 0 })?;
/// let listener = bind_tcp(&addr).await?;
/// serve_with_graceful_shutdown(listener, Router::new(), async {
///     let _ = signal::ctrl_c().await;
/// })
/// .await?;
/// # Ok(())
/// # }
/// ```
pub async fn serve_with_graceful_shutdown(
    listener: tokio::net::TcpListener,
    app: Router<()>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let addr = listener.local_addr().ok();
    tracing::info!(?addr, graceful = true, "soliton serve starting");
    match axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
    {
        Ok(()) => {
            tracing::info!(?addr, "soliton serve stopped after graceful shutdown");
            Ok(())
        }
        Err(err) => {
            tracing::error!(?addr, error = %err, "soliton serve failed");
            Err(err.into())
        }
    }
}
