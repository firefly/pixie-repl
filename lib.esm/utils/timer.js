/**
 *  Returns a **Promise** that will resolve after %%duration%%.
 */
export function stall(duration) {
    return new Promise((resolve) => {
        setTimeout(resolve, duration);
    });
}
//# sourceMappingURL=timer.js.map