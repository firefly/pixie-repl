/**
 *  Returns a **Promise** that will resolve after %%duration%%.
 */
export function stall(duration: number): Promise<void> {
    return new Promise((resolve) => {
        setTimeout(resolve, duration);
    });
}
