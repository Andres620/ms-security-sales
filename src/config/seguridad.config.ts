export namespace ConfiguracionSeguridad {
  export const claveJWT = process.env.SECRET_PASSWORD_JWT;
  export const menuUsuarioID = '65a2e39a41556e2bc4e396de';
  export const listarAccion = 'listar';
  export const guardarAccion = 'guardar';
  export const editarAccion = 'editar';
  export const eliminarAccion = 'eliminar';
  export const descargarAccion = 'descargar';
  export const mongodbConnectionString = process.env.CONNECTION_STRING_MONGODB;
}
