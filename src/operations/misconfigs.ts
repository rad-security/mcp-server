import { z } from "zod";
import { RadSecurityClient } from "../client.js";

export const ListKubernetesResourceMisconfigurationsSchema = z.object({
  resource_uid: z.string().describe("Kubernetes resource UID to get misconfigurations for"),
});

export const GetKubernetesResourceMisconfigurationDetailsSchema = z.object({
  cluster_id: z.string().describe("ID of the cluster to get misconfiguration for"),
  misconfig_id: z.string().describe("ID of the misconfiguration to get details for"),
});

export const ListKubernetesResourceMisconfigurationPoliciesSchema = z.object({
  // Empty schema as the function doesn't take parameters
}).describe("Get a list of available misconfiguration policies");

export async function listKubernetesResourceMisconfigurations(
  client: RadSecurityClient,
  resourceUid: string
): Promise<any> {
  const misconfigs = await client.makeRequest(
    `/accounts/${client.getAccountId()}/misconfig`,
    { kubeobject_uids: resourceUid, page_size: 50 }
  );

  // deduplicate the list based on field "guard_policy.human_id"
  const seenIds = new Set<string>();
  const toReturn = [];

  for (const misconfig of misconfigs.entries) {
    const humanId = misconfig.guard_policy.human_id;
    if (!seenIds.has(humanId)) {
      seenIds.add(humanId);
      toReturn.push({
        id: misconfig.id,
        cluster_id: misconfig.cluster_id,
        title: misconfig.guard_policy.title,
        human_id: misconfig.guard_policy.human_id,
      });
    }
  }

  misconfigs.entries = toReturn;
  return misconfigs;
}

export async function getKubernetesResourceMisconfigurationDetails(
  client: RadSecurityClient,
  clusterId: string,
  misconfigId: string
): Promise<any> {
  const response = await client.makeRequest(
    `/accounts/${client.getAccountId()}/clusters/${clusterId}/misconfig/${misconfigId}`
  );

  if (!response) {
    throw new Error(`No misconfiguration found with ID: ${misconfigId}`);
  }

  return response;
}

export async function listKubernetesResourceMisconfigurationPolicies(): Promise<any> {
  const policies = [
    {
      id: "RAD-K8S-KUBELET-HTTPS",
      title: "Kubelet has unencrypted communications",
      description:
        "Connections from the apiserver to the kubelet(s) could potentially carry sensitive data such as secrets and keys. It is thus important to use in-transit encryption for any communication between the apiserver and kubelet(s). Kubelet containers found with --kubelet-https set to false should be set to true for in-transit encryption for any communication between the apiserver and kubelet(s).",
    },
    {
      id: "RAD-K8S-PRIVILEGED-CONTAINERS",
      title: "Container(s) set to run in privileged context",
      description:
        "Privileged containers have all of the root capabilities of a host machine, allowing access to resources that are not accessible in ordinary containers. Common uses of privileged containers include: running a Docker daemon inside a Docker container, running a container with direct hardware access, and automating CI/CD tasks. Containers discovered where securityContext.privileged is set to true should be set to false.",
    },
    {
      id: "RAD-K8S-RUNNING-AS-ROOT",
      title: "Container(s) set to run as root",
      description:
        "A workload is running as the root user which typically has excessive permissions on the host operating system. Containers should reduce permissions to only what is necessary and nothing more. Containers discovered where securityContext.runAsNonRoot is not set to true or securityContext.runAsUser is not > 0 should have securityContext.runAsUser set to 10000 or higher.",
    },
    {
      id: "RAD-K8S-READONLY-FILESYSTEM",
      title: "A read-only root filesystem is not being used for the container(s)",
      description:
        "A read-only root filesystem helps to enforce an immutable infrastructure strategy. The container should only write on mounted volumes that can persist, even if the container exits. Containers discovered where securityContext.readOnlyRootFilesystem was not set as true should be set as true.",
    },
    {
      id: "RAD-K8S-RUN-AS-HIGH-UID",
      title: "Container(s) not running with a high UID",
      description:
        "To prevent privilege-escalation attacks from within a container, we recommend that you configure your container's applications to run as unprivileged users. Ensuring containers run with a UID over 10000 avoids host conflicts and can stop a malicious process from elevating privileges outside of a given namespace. Containers discovered where securityContext.runAsUser not set > 10000 should be set > 10000.",
    },
    {
      id: "RAD-K8S-PRIV-ESC",
      title: "Container(s) allow privilege escalation",
      description:
        "The AllowPrivilegeEscalation Pod Security Policy controls whether or not a user is allowed to set the security context of a container to True. Setting it to False ensures that no child process of a container can gain more privileges than its parent. Containers discovered where securityContext.allowPrivilegeEscalation is set as true should be set as false.",
    },
    {
      id: "RAD-K8S-IMAGE-LATEST",
      title: "Container(s) image tag is set to latest",
      description:
        "The :latest tag is used to indicate that the image is the latest version of the image. This tag is not recommended for use in production as it is more difficult to track the exact version of the image running. Containers discovered where image is set as latest should be set as a specific version and update them when new versions are available that have been evaluated for security and application compatibility.",
    },
    {
      id: "RAD-K8S-CPU-REQUESTS",
      title: "Minimum CPU resources are not set for container(s)",
      description:
        "Without setting requests CPU for containers, containers may not have enough CPU resources to run. Containers discovered where resources.requests.cpu is not set should be set so that container is guaranteed to be allocated as much CPU as it requests.",
    },
    {
      id: "RAD-K8S-MEM-LIMIT",
      title: "Memory limits are not set for container(s)",
      description:
        "Without setting memory limits for containers, containers may use more than the expected amount of memory. This may cause cluster-wide performance degradation issues or even complete failures. Containers discovered where resources.limits.memory is not set.",
    },
    {
      id: "RAD-K8S-CPU-LIMIT",
      title: "CPU limits are not set for container(s)",
      description:
        "Without setting CPU limits for containers, containers may use more than the expected amount of CPU. This may cause cluster-wide performance degradation issues or even complete failures. Remediation: Containers were discovered where resources.limits.cpu is not set. Set container resources.limits.cpu limits for all containers.",
    },
    {
      id: "RAD-K8S-CAP-SYSADMIN",
      title: "CAP_SYS_ADMIN Linux capability is in use in container(s)",
      description:
        "Certain Linux capabilities can grant root-level access to the host. CAP_SYS_ADMIN is extremely privileged and should be avoided when possible. Containers discovered where securityContext.capabilities.add include SYS_ADMIN should have it removed.",
    },
    {
      id: "RAD-K8S-HOST-PID",
      title: "Host PID flag set to true in container(s)",
      description:
        "Do not generally permit containers to be run with the hostPID flag set to true. Containers were discovered where spec.template.spec.hostPID was set to true. Set them to false.",
    },
    {
      id: "RAD-K8S-HOST-IPC",
      title: "hostIPC flag set to true in container(s)",
      description:
        "Do not generally permit containers to be run with the hostIPC flag set to true. Containers were discovered where spec.template.spec.hostIPC was set to true. Set them to false.",
    },
    {
      id: "RAD-K8S-HOST-NETWORK",
      title: "hostNetwork flag set to true",
      description:
        "Do not generally permit containers to be run with the hostNetwork flag set to true. Containers were discovered where spec.template.spec.hostNetwork was set to true. Set them to false.",
    },
    {
      id: "RAD-K8S-NET-RAW",
      title: "NET_RAW capability detected in container(s)",
      description:
        "Do not generally permit containers with the potentially dangerous NET_RAW capability. Containers were discovered where securityContext.capabilities.add included NET_RAW or ALL. Remove NET_RAW and ALL from all container securityContext.capabilities.add lists.",
    },
    {
      id: "RAD-K8S-SECCOMP-PROFILE",
      title: "seccompProfile not included in container(s)",
      description:
        "Ensure that there is a seccomp profile in your pod and/or container definitions. Containers were discovered where securityContext.seccompProfile was not included or misconfigured. Include a securityContext.seccompProfile definition for all containers and preferrably use type Local with a local host profile.",
    },
    {
      id: "RAD-K8S-KUBEAPI-AUDIT-LOG-PATH",
      title: "audit-log-path not set in kube-apiserver container",
      description:
        "Exporting logs and metrics to a dedicated, persistent datastore ensures availability of audit data following a cluster security event, and provides a central location for analysis of log and metric data collated from multiple sources. Remediation: Container kube-apiserver command kube-apiserver list does not include --audit-log-path path. Add a path to .log file path in command --audit-log-path in kube-apiserver container.",
    },
    {
      id: "RAD-K8S-KUBEAPI-AUDIT-POLICY-FILE-PATH",
      title: "audit-policy-file path not set in kube-apiserver container",
      description:
        "Exporting logs and metrics to a dedicated, persistent datastore ensures availability of audit data following a cluster security event, and provides a central location for analysis of log and metric data collated from multiple sources.Container kube-apiserver command kube-apiserver list does not include --audit-policy-file path. Add a path to policy yaml file path in command --audit-policy-file in kube-apiserver container.",
    },
    {
      id: "RAD-K8S-KUBEAPI-AUDIT-LOG-MAXAGE",
      title: "audit-log-maxage not set in kube-apiserver container",
      description:
        "Exporting logs and metrics to a dedicated, persistent datastore ensures availability of audit data following a cluster security event, and provides a central location for analysis of log and metric data collated from multiple sources.Container kube-apiserver command kube-apiserver list does not include --audit-log-maxage setting. Add a setting in command --audit-log-maxage in kube-apiserver container.",
    },
    {
      id: "RAD-K8S-KUBEAPI-AUDIT-LOG-MAXBACKUP",
      title: "audit-log-maxbackup not set in kube-apiserver container",
      description:
        "Exporting logs and metrics to a dedicated, persistent datastore ensures availability of audit data following a cluster security event, and provides a central location for analysis of log and metric data collated from multiple sources.Container kube-apiserver command kube-apiserver list does not include --audit-log-maxbackup setting. Add a setting in command --audit-log-maxbackup in kube-apiserver container.",
    },
    {
      id: "RAD-K8S-KUBEAPI-AUDIT-LOG-MAXSIZE",
      title: "audit-log-maxsize not set in kube-apiserver container",
      description:
        "Exporting logs and metrics to a dedicated, persistent datastore ensures availability of audit data following a cluster security event, and provides a central location for analysis of log and metric data collated from multiple sources.Container kube-apiserver command kube-apiserver list does not include --audit-log-maxsize setting. Add a setting in command --audit-log-maxsize in kube-apiserver container.",
    },
    {
      id: "RAD-K8S-ROLE-CLUSTERADMIN",
      title: "Ensure that the cluster-admin role is only used where required",
      description:
        "The RBAC role cluster-admin provides wide-ranging powers over the environment and should be used only where and when needed. Unbind cluster-admin from all service accounts unless absolutely needed.",
    },
    {
      id: "RAD-K8S-SECRETS-ACCESS",
      title: "Minimize access to secrets",
      description:
        "The Kubernetes API stores secrets, which may be service account tokens for the Kubernetes API or credentials used by workloads in the cluster. Access to these secrets should be restricted to the smallest possible group of users to reduce the risk of privilege escalation. Remove the verbs 'get', 'list', and 'watch' for all Role and ClusterRole 'secrets' resources.",
    },
    {
      id: "RAD-K8S-WILDCARD-APIGROUPS",
      title: "Minimize wildcard use in Roles and ClusterRoles:ApiGroups",
      description:
        "Kubernetes Roles and ClusterRoles provide access to resources based on sets of objects and actions that can be taken on those objects. It is possible to set either of these to be the wildcard \"*\" which matches all items. Use of wildcards is not optimal from a security perspective as it may allow for inadvertent access to be granted when new resources are added to the Kubernetes API either as CRDs or in later versions of the product.Remediation: Remove wildcards in Role and ClusterRole apiGroups.",
    },
    {
      id: "RAD-K8S-WILDCARD-RESOURCES",
      title: "Minimize wildcard use in Roles and ClusterRoles:Resources",
      description:
        "Kubernetes Roles and ClusterRoles provide access to resources based on sets of objects and actions that can be taken on those objects. It is possible to set either of these to be the wildcard \"*\" which matches all items. Use of wildcards is not optimal from a security perspective as it may allow for inadvertent access to be granted when new resources are added to the Kubernetes API either as CRDs or in later versions of the product. Remove wildcards in Role and ClusterRole resources.",
    },
    {
      id: "RAD-K8S-WILDCARD-VERBS",
      title: "Minimize wildcard use in Roles and ClusterRoles:Verbs",
      description:
        "Kubernetes Roles and ClusterRoles provide access to resources based on sets of objects and actions that can be taken on those objects. It is possible to set either of these to be the wildcard \"*\" which matches all items. Use of wildcards is not optimal from a security perspective as it may allow for inadvertent access to be granted when new resources are added to the Kubernetes API either as CRDs or in later versions of the product. Remediation: Remove wildcards in Role and ClusterRole verbs.",
    },
    {
      id: "RAD-K8S-CREATE-PODS",
      title: "Minimize access to create pods",
      description:
        "The ability to create pods in a namespace can provide a number of opportunities for privilege escalation, such as assigning privileged service accounts to these pods or mounting hostPaths with access to sensitive data (unless Pod Security Policies are implemented to restrict this access). As such, access to create new pods should be restricted to the smallest possible group of users. Remediation: Remove verb 'create' for resources 'pods' in Role and ClusterRole definitions unless absolutely necessary.",
    },
    {
      id: "RAD-K8S-DEFAULT-SERVICEACCOUNT",
      title: "Ensure that default service accounts are not actively used.",
      description:
        "The default service account should not be used to ensure that rights granted to applications can be more easily audited and reviewed. Remediation: Remove kind 'ServiceAccount' with name 'default' from RoleBinding subjects except when absolutely needed.",
    },
    {
      id: "RAD-K8S-SERVICEACCOUNTTOKEN-MOUNTED",
      title: "Ensure that service account tokens are only mounted where necessary",
      description:
        "Service accounts tokens should not be mounted in pods except where the workload running in the pod explicitly needs to communicate with the API server. Remediation: Remove kind 'ServiceAccount' with name 'default' from RoleBinding subjects except when absolutely needed.",
    },
    {
      id: "RAD-K8S-SERVICEACCOUNTTOKEN-MOUNTED-POD",
      title: "Ensure that Service Account Tokens are only mounted where necessary in Pods",
      description:
        "Service accounts tokens should not be mounted in pods except where the workload running in the pod explicitly needs to communicate with the API server. Remediation: ServiceAccount automountServiceAccountToken found not set to false. Service accounts tokens should not be mounted in pods except where the workload running in the pod explicitly needs to communicate with the API server.",
    },
    {
      id: "RAD-K8S-CAPABILITIES-ADDED",
      title: "Container(s) running with added capabilities",
      description:
        "Do not generally permit containers with capabilities assigned beyond the default set. Remediation: Containers were discovered with added capabilities in 'securityContext.capabilities.add'. Remove 'securityContext.capabilities.add' from all containers unless explicitly needed. In such cases, limit the added capabilities.",
    },
    {
      id: "RAD-K8S-CAPABILITIES-DROPALL",
      title: "Container(s) running without capabilities.drop set to all",
      description:
        "Containers run with a default set of capabilities as assigned by the Container Runtime. Capabilities are parts of the rights generally granted on a Linux system to the root user. In many cases applications running in containers do not require any capabilities to operate, so from the perspective of the principle of least privilege use of capabilities should be minimized. Remediation: Containers were discovered without 'securityContext.capabilities.drop' explicitly set with 'ALL'. Add 'securityContext.capabilities.drop' with value 'ALL' to all containers whenever possible.",
    },
    {
      id: "RAD-K8S-SECRETS_ENV-VAR",
      title: "Prefer using secrets as files over secrets as environment variables",
      description:
        "It is reasonably common for application code to log out its environment (particularly in the event of an error). This will include any secret values passed in as environment variables, so secrets can easily be exposed to any user or entity who has access to the logs. Remediation: Containers were discovered that include secret keys as environment in container.env.valueFrom.secretKeyRef.name and container.env.valueFrom.secretKeyRef.key values. They should be removed from all containers and replaceed with secrets used as files.",
    },
    {
      id: "RAD-K8S-SECURITYCONTEXT",
      title: "Container(s) running without defined securityContext",
      description:
        "A security context defines the operating system security settings (uid, gid, capabilities, SELinux role, etc..) applied to a container. When designing your containers and pods, make sure that you configure the security context for your pods, containers, and volumes. A security context is a property defined in the deployment yaml. It controls the security parameters that will be assigned to the pod/container/volume. There are two levels of security context: pod level security context, and container level security context. Remediation: Containers were discovered that did not include container.securityContext settings. Add container.securityContext settings to all containers.",
    },
    {
      id: "RAD-K8S-SECURITYCONTEXT-POD",
      title: "Pod running without defined securityContext",
      description:
        "A security context defines the operating system security settings (uid, gid, capabilities, SELinux role, etc..) applied to a container. When designing your containers and pods, make sure that you configure the security context for your pods, containers, and volumes. A security context is a property defined in the deployment yaml. It controls the security parameters that will be assigned to the pod/container/volume. There are two levels of security context: pod level security context, and container level security context. Remediation: Pods were discovered that did not include spec.securityContext settings. Add spec.securityContext settings to all pods.",
    },
    {
      id: "RAD-K8S-NAMESPACE-DEFAULT",
      title: "Workload running in default namespace",
      description:
        "Kubernetes provides a default namespace, where objects are placed if no namespace is specified for them. Placing objects in this namespace makes application of RBAC and other controls more difficult. Remediation: Workloads and/or Pods were discovered missing metadata.namespace setting or with metadata.namespace set as 'default'. Workloads and Pods should have metadata.namespace explicitly set to a namespace other than 'default'.",
    },
    {
      id: "RAD-K8S-PERMISSIONS-ESCALATION",
      title: "Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster",
      description:
        "Cluster roles and roles with the impersonate, bind or escalate permissions should not be granted unless strictly required. Each of these permissions allow a particular subject to escalate their privileges beyond those explicitly granted by cluster administrators. Remediation: Role or ClusterRole rule.verbs include one or more of the verbs 'impersonate', 'bind', 'escalate', or '*'. Remove these verbs from Role and ClusterRole rule.verbs unless explicitely needed.",
    },
    {
      id: "RAD-K8S-HOSTPATH-VOLUME",
      title: "Minimize the admission of hostPath volumes",
      description:
        "Do not generally admit containers which make use of hostPath volumes. Remediation: Containers found with container.volume mount with volume.hostPath set. Avoid the use of containers with hostpath volumes.",
    },
    {
      id: "RAD-K8S-HOSTPORT",
      title: "Minimize the admission of containers which use hostPort",
      description:
        "Do not generally permit containers which require the use of HostPorts. Remediation: Containers found with container.hostPort set. Avoid the use of containers with hostPort set.",
    },
    {
      id: "RAD-K8S-KUBEAPISERVER-INSECURE-PORT",
      title: "Kubernetes API server running with insecure-port set to non-zero value",
      description:
        "By default, the API server will listen on two ports. One port is the secure port and the other port is called the \"localhost port\". This port is also called the \"insecure port\", port 8080. Any requests to this port bypass authentication and authorization checks. If this port is left open, anyone who gains access to the host on which the master is running can bypass all authorization and authentication mechanisms put in place, and have full control over the entire cluster. Close the insecure port by setting the API server's --insecure-port flag to \"0\", ensuring that the --insecure-bind-address is not set. Remediation: kube-apiserver container found with --insecure-port set. It should be set with --insecure-port=0 to avoid authorization and authentication bypassing.",
    },
    {
      id: "RAD-K8S-KUBEAPISERVER-INSECURE-BINDADDRESS",
      title: "Kubernetes API server running with insecure-bind-address set",
      description:
        "By default, the API server will listen on two ports and addresses. One address is the secure address and the other address is called the \"insecure bind\" address and is set by default to localhost. Any requests to this address bypass authentication and authorization checks. If this insecure bind address is set to localhost, anyone who gains access to the host on which the master is running can bypass all authorization and authentication mechanisms put in place and have full control over the entire cluster. Close or set the insecure bind address by setting the API server's --insecure-bind-address flag to an IP or leave it unset and ensure that the --insecure-port is not set. Remediation: kube-apiserver container found with --insecure-bind-address set. It should be unset avoid authorization and authentication bypassing.",
    },
    {
      id: "RAD-K8S-KUBELET-ANONYMOUSAUTH",
      title: "Kubernetes API server running with anonymous-auth enabled",
      description:
        "The Kubernetes API Server controls Kubernetes via an API interface. A user who has access to the API essentially has root access to the entire Kubernetes cluster. To control access, users must be authenticated and authorized. By allowing anonymous connections, the controls put in place to secure the API can be bypassed. Setting anonymous authentication to 'false' also disables unauthenticated requests from kubelets. While there are instances where anonymous connections may be needed (e.g., health checks) and Role-Based Access Controls (RBAC) are in place to limit the anonymous access, this access should be disabled, and only enabled when necessary. Remediation: kublet container found with --anonymous-auth set to true. It should be set to false to disable unauthenticated request from kubelets.",
    },
    {
      id: "RAD-K8S-DASHBOARD",
      title: "Kubernetes dashboard is enabled",
      description:
        "The Kubernetes Web UI (Dashboard) has been a historical source of vulnerability and should only be deployed when necessary. Remediation: kubernetes-dashboard container found. It should not be deployed unless necessary.",
    },
    {
      id: "RAD-K8S-AUDITPOLICY-OMITSTAGES-GLOBAL",
      title: "Kubernetes API Server must generate verbose audit records:OmitStagesGlobal",
      description:
        "Within Kubernetes, audit data for all components is generated by the API server. This audit data is important when there are issues, to include security incidents that must be investigated. To make the audit data worthwhile for the investigation of events, it is necessary to have the appropriate and required data logged. To fully understand the event, it is important to identify any users associated with the event. There should be a single audit policy rule set with level RequestResponse. Remediation: Audit policy found with global omitStages set. There should be a single audit policy rule set with level RequestResponse for all resources without omitStages.",
    },
    {
      id: "RAD-K8S-AUDITPOLICY-OMITSTAGES",
      title: "Kubernetes API Server must generate verbose audit records:OmitStages",
      description:
        "Within Kubernetes, audit data for all components is generated by the API server. This audit data is important when there are issues, to include security incidents that must be investigated. To make the audit data worthwhile for the investigation of events, it is necessary to have the appropriate and required data logged. To fully understand the event, it is important to identify any users associated with the event. There should be a single audit policy rule set with level RequestResponse. Remediation: Audit policy found with omitStages set. There should be a single audit policy rule set with level RequestResponse for all resources without omitStages.",
    },
    {
      id: "RAD-K8S-AUDITPOLICY-SPECIFIED-RESOURCES",
      title: "Kubernetes API Server must generate verbose audit records:SpecifiedResources",
      description:
        "Within Kubernetes, audit data for all components is generated by the API server. This audit data is important when there are issues, to include security incidents that must be investigated. To make the audit data worthwhile for the investigation of events, it is necessary to have the appropriate and required data logged. To fully understand the event, it is important to identify any users associated with the event. There should be a single audit policy rule set with level RequestResponse. Remediation: Audit policy found with resources set. There should be a single audit policy rule set with level RequestResponse for all resources without omitStages.",
    },
    {
      id: "RAD-K8S-AUDITPOLICY-REQUESTRESPONSE",
      title: "Kubernetes API Server must generate verbose audit records:UnsetRequestResponse",
      description:
        "Within Kubernetes, audit data for all components is generated by the API server. This audit data is important when there are issues, to include security incidents that must be investigated. To make the audit data worthwhile for the investigation of events, it is necessary to have the appropriate and required data logged. To fully understand the event, it is important to identify any users associated with the event. There should be a single audit policy rule set with level RequestResponse. Remediation: Audit policy found without level RequestResponse set. There should be a single audit policy rule set with level RequestResponse for all resources without omitStages.",
    },
    {
      id: "RAD-K8S-KUBEAPISERVER-REDIRECT-CVE-2022-3172",
      title: "Kubernetes API server susceptible to CVE-2022-3172",
      description:
        "CVE-2022-3172: A security issue was discovered in kube-apiserver that allows an aggregated API server to redirect client traffic to any URL. This could lead to the client performing unexpected actions as well as forwarding the client's API server credentials to third parties. Remediation: Upgrade to the latest version of kube-apiserver.",
    },
    {
      id: "RAD-K8S-MEM-REQUESTS",
      title: "Minimum memory resources are not set for container(s)",
      description:
        "Without setting requests memory for containers, containers may not have enough memory resources to run. Remediation: Containers were discovered where resources.requests.memory is not set. Set container resources.requests.memory for all containers.",
    },
    {
      id: "RAD-K8S-IMAGE-PULLPOLICY",
      title: "Container(s) image imagePullPolicy",
      description:
        "The Image Pull Policy should be set to Always to ensure the correct image and imagePullSecrets. Remediation: Containers were discovered where imagePullPolicy is not set to Always. Set container imagePullPolicy=\"Always\".",
    },
    {
      id: "RAD-K8S-SYSTEM-MASTERS",
      title: "Limit access to group system:masters",
      description:
        "The special group system:masters should not be used to grant permissions to any user or service account, except where strictly necessary (e.g. bootstrapping access prior to RBAC being fully available)",
    },
  ];

  return {
    entries: policies,
    size: policies.length,
    has_more: false,
    metadata: {
      total_count: policies.length,
    },
  };
}
