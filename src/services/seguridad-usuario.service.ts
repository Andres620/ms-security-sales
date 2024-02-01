import {/* inject, */ BindingScope, injectable} from '@loopback/core';
import {repository} from '@loopback/repository';
import {ConfiguracionSeguridad} from '../config/seguridad.config';
import {Credenciales, FactorDeAutenticacionPorCodigo, Usuario} from '../models';
import {LoginRepository, UsuarioRepository} from '../repositories';
const generator = require('generate-password');
const MD5 = require('crypto-js/md5');
const jwt = require('jsonwebtoken');

@injectable({scope: BindingScope.TRANSIENT})
export class SeguridadUsuarioService {
  constructor(
    @repository(UsuarioRepository)
    public repositorioUsuario: UsuarioRepository,
    @repository(LoginRepository)
    public repositorioLogin: LoginRepository,
  ) {}

  /**
   * Crear clave aleatoria
   * @returns cadena aleatoria de n caracteres
   */
  crearTextoAleatorio(n: number): string {
    let clave = generator.generate({
      length: n,
      numbers: true,
    });
    return clave;
  }

  /**
   * Cifrar una cadena de texto con método MD5
   * @param cadena cadena de texto a cifrar
   * @returns cadena cifrada con md5
   */
  cifrarTexto(cadena: string): string {
    let cadenaCifrada = MD5(cadena).toString();
    return cadenaCifrada;
  }

  /**
   * Se busca un usuario por sus credenciales (correo y clave)
   * @param credenciales credenciales del usuario
   * @returns usuario encontrado o null
   */
  async identificarUsuario(
    credenciales: Credenciales,
  ): Promise<Usuario | null> {
    let usuario = await this.repositorioUsuario.findOne({
      where: {
        correo: credenciales.correo,
        clave: credenciales.clave,
      },
    });

    return usuario as Usuario;
  }

  /**
   * Valida un código de 2fa para un usuario
   * @param credenciales2fa credenciales del usuario con el códifo de 2fa
   * @returns el registro de login o null
   */
  async validarCodigo2fa(
    credenciales2fa: FactorDeAutenticacionPorCodigo,
  ): Promise<Usuario | null> {
    let login = await this.repositorioLogin.findOne({
      where: {
        usuarioId: credenciales2fa.usuarioId,
        codigo2fa: credenciales2fa.codigo2fa,
        estadoCodigo2fa: false, // si es falso ya fue utilizado y no lo puedo vovler a utilizar
      },
    });
    if (login) {
      let usuario = await this.repositorioUsuario.findById(
        credenciales2fa.usuarioId,
      );
      return usuario;
    }
    return null;
  }

  /**
   * Generación de un token JWT para un usuario
   * @param usuario información dle usuario
   * @returns token
   */
  crearToken(usuario: Usuario): string {
    let datos = {
      name: `${usuario.primerNombre} ${usuario.segundoNombre} ${usuario.primerApellido} ${usuario.segundoApellido}`,
      role: usuario.rolId,
      email: usuario.correo,
    };
    let token = jwt.sign(datos, ConfiguracionSeguridad.claveJWT);
    return token;
  }

  /**
   * Validay obtiene el rol de un token
   * @param tk el token
   * @returns el _id del rol
   */
  obtenerRolDesdeToken(tk: string): string {
    try {
      let obj = jwt.verify(tk, ConfiguracionSeguridad.claveJWT);
      return obj.role;
    } catch (error) {
      console.error('Error al verificar el token:', error);
      return '';
    }
  }
}
