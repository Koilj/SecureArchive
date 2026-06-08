if (window.location.hostname === "127.0.0.1") {
  const port = window.location.port ? `:${window.location.port}` : "";
  const target = `${window.location.protocol}//localhost${port}${window.location.pathname}${window.location.search}${window.location.hash}`;
  window.location.replace(target);
}
