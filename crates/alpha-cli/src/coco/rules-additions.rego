######################################################################
# Additions

allow_env_present(p_var, i_process) if {
    p_var == "HOSTNAME=$(host-name)"
}
allow_env_present(p_var, i_process) if {
    some i_var in i_process.Env
    i_var == p_var
}
allow_var(p_process, i_process, i_var, s_name, s_namespace) if {
    some p_var in p_process.Env
    p_var == "HOSTNAME=$(host-name)"
    i_var == concat("", ["HOSTNAME=", s_name])
    print("allow_var hostname: true")
}

image_pull_metadata(i_storage) := m if {
    some opt in i_storage.driver_options
    startswith(opt, "image_guest_pull=")
    m := json.unmarshal(trim_prefix(opt, "image_guest_pull=")).metadata
}

allow_image(p_oci, i_oci, i_storages) if {
    i_oci.Annotations["io.kubernetes.cri.container-type"] == "sandbox"
    pulls := [s | some s in i_storages; s.driver == "image_guest_pull"]
    count(pulls) == 1
    image_pull_metadata(pulls[0])["io.kubernetes.cri.container-type"] == "sandbox"
    print("allow_image: sandbox uses the guest pause bundle")
}
allow_image(p_oci, i_oci, i_storages) if {
    i_oci.Annotations["io.kubernetes.cri.container-type"] == "container"
    p_image := p_oci.Annotations["io.kubernetes.cri.image-name"]
    regex.match("@sha256:[0-9a-f]{64}$", p_image)
    pulls := [s | some s in i_storages; s.driver == "image_guest_pull"]
    print("allow_image: p_image =", p_image, "pulls =", [s.source | some s in pulls])
    count(pulls) == 1
    pulls[0].source == p_image
    image_pull_metadata(pulls[0])["io.kubernetes.cri.container-type"] == "container"
    print("allow_image: true")
}
