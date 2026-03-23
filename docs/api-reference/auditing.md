<p>Packages:</p>
<ul>
<li>
<a href="#auditing.extensions.gardener.cloud%2fv1alpha1">auditing.extensions.gardener.cloud/v1alpha1</a>
</li>
</ul>
<h2 id="auditing.extensions.gardener.cloud/v1alpha1">auditing.extensions.gardener.cloud/v1alpha1</h2>
<p>
<p>Package v1alpha1 is a version of the API.</p>
</p>
Resource Types:
<ul></ul>
<h3 id="auditing.extensions.gardener.cloud/v1alpha1.AuditBackend">AuditBackend
</h3>
<p>
(<em>Appears on:</em>
<a href="#auditing.extensions.gardener.cloud/v1alpha1.AuditConfiguration">AuditConfiguration</a>)
</p>
<p>
<p>AuditBackend defines the configuration for a single audit backend.
It specifies where audit events should be sent and how they should be delivered.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>deliveryMode</code></br>
<em>
github.com/gardener/auditlog-forwarder/pkg/apis/config/v1alpha1.DeliveryMode
</em>
</td>
<td>
<em>(Optional)</em>
<p>DeliveryMode specifies how messages are delivered to this backend.
&ldquo;Guaranteed&rdquo; means the request is considered successful only if this backend succeeds.
&ldquo;BestEffort&rdquo; means delivery is attempted but failures don&rsquo;t affect request success.
When only one backend is configured, it is implicitly &ldquo;Guaranteed&rdquo;.
When multiple backends are configured, exactly one must be &ldquo;Guaranteed&rdquo;.</p>
</td>
</tr>
<tr>
<td>
<code>http</code></br>
<em>
<a href="#auditing.extensions.gardener.cloud/v1alpha1.BackendHTTP">
BackendHTTP
</a>
</em>
</td>
<td>
<p>HTTP specifies the configuration for an HTTP-based audit backend.
When configured, audit events will be sent via HTTP to the specified endpoint.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="auditing.extensions.gardener.cloud/v1alpha1.AuditConfiguration">AuditConfiguration
</h3>
<p>
<p>AuditConfiguration contains information about the auditing service configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>backends</code></br>
<em>
<a href="#auditing.extensions.gardener.cloud/v1alpha1.AuditBackend">
[]AuditBackend
</a>
</em>
</td>
<td>
<p>Backends are all the backends that will receive audit logs.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="auditing.extensions.gardener.cloud/v1alpha1.BackendHTTP">BackendHTTP
</h3>
<p>
(<em>Appears on:</em>
<a href="#auditing.extensions.gardener.cloud/v1alpha1.AuditBackend">AuditBackend</a>)
</p>
<p>
<p>BackendHTTP defines the configuration for an HTTP audit backend.
This backend sends audit events to a remote HTTP endpoint over HTTPS.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>url</code></br>
<em>
string
</em>
</td>
<td>
<p>URL is the HTTP endpoint where audit events will be sent.
This should be a complete HTTPS URL including the protocol, host, and path.</p>
</td>
</tr>
<tr>
<td>
<code>tls</code></br>
<em>
<a href="#auditing.extensions.gardener.cloud/v1alpha1.TLSConfig">
TLSConfig
</a>
</em>
</td>
<td>
<p>TLS contains the TLS configuration for secure communication with the HTTP backend.</p>
</td>
</tr>
<tr>
<td>
<code>compression</code></br>
<em>
string
</em>
</td>
<td>
<p>Compression defines the compression algorithm to use for the HTTP request body when forwarding
audit events. If unset, no compression is applied. Currently only &ldquo;gzip&rdquo; is supported.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="auditing.extensions.gardener.cloud/v1alpha1.TLSConfig">TLSConfig
</h3>
<p>
(<em>Appears on:</em>
<a href="#auditing.extensions.gardener.cloud/v1alpha1.BackendHTTP">BackendHTTP</a>)
</p>
<p>
<p>TLSConfig defines the TLS configuration for secure communication.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>secretReferenceName</code></br>
<em>
string
</em>
</td>
<td>
<p>SecretReferenceName is the name reference that leads to a Secret containing the TLS configuration.
The secret should contain &ldquo;client.crt&rdquo;, &ldquo;client.key&rdquo; (used for mTLS) and optionally &ldquo;ca.crt&rdquo; (used for verifying the server&rsquo;s certificate) keys.</p>
</td>
</tr>
</tbody>
</table>
<hr/>
<p><em>
Generated with <a href="https://github.com/ahmetb/gen-crd-api-reference-docs">gen-crd-api-reference-docs</a>
</em></p>
