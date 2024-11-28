
export function clone(name, values) {
    const node = document.getElementById(`template-${ name }`).cloneNode(true);
    node.removeAttribute("id");
    node.classList.add(name);
    if (values) {
        for (const key in values) {
            const value = values[key];
            node.querySelectorAll(`.${ key }`).forEach((e) => {
                if (typeof(value) === "string" || typeof(value) === "number") {
                    e.innerText = value;
                } else if (value instanceof Node) {
                    e.appendChild(value);
                } else {
                    console.log("got", e, { key, value });
                }
            });
        }
        /*
        node.querySelectorAll("[data-keys]").forEach((e) => {
            const keys = (e.getAttribute("data-keys") || "").split(/ /g);
            console.log({ keys });
            keys.forEach((key) => {
                e.setAttribute(`data-${ key }`, values[key] || "");
            });
        });
        */
    }
    return node;
}
