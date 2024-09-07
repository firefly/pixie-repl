declare module "ioctl" {
  function ioctl(fd: number, request: number, data?: Buffer): void;
  export default ioctl;
}
