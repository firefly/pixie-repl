
export function stall(duration) {
    return new Promise((resolve) => {
        setTimeout(resolve, duration);
    });
}
