/** ESTA ESTRATEGIA ES UN INTERCEPTOR ENTRE EL CLIENTE Y EL CONTROLADOR */

import {
  AuthenticationBindings,
  AuthenticationMetadata,
  AuthenticationStrategy,
} from '@loopback/authentication';
import {inject, service} from '@loopback/core';
import {repository} from '@loopback/repository';
import {HttpErrors, Request} from '@loopback/rest';
import {UserProfile} from '@loopback/security';
import parseBearerToken from 'parse-bearer-token';
import {RolMenuRepository} from '../repositories';
import {AuthService, SeguridadUsuarioService} from '../services';

export interface Credentials {
  username: string;
  password: string;
}

export class AuthStrategy implements AuthenticationStrategy {
  name: string = 'auth';

  constructor(
    @service(SeguridadUsuarioService)
    private servicioSeguridad: SeguridadUsuarioService,
    @inject(AuthenticationBindings.METADATA)
    private metadata: AuthenticationMetadata[],
    @repository(RolMenuRepository)
    private repositorioRolMenu: RolMenuRepository,
    @service(AuthService)
    private servicioAuth: AuthService,
  ) {}

  /**
   * Autenticación de un usuario frente a una acción en la base de datos
   * @param request la solicitud con el token
   * @returns el perfil de usuario, undefined si no tiene permisos o HttpErrors[401]
   */
  async authenticate(request: Request): Promise<UserProfile | undefined> {
    let token = parseBearerToken(request);
    if (token) {
      let idRol = this.servicioSeguridad.obtenerRolDesdeTojen(token);
      let idMenu = this.metadata[0].options![0];
      let accion = this.metadata[0].options![1];
      console.log('Metadata', this.metadata);
      try {
        let res = await this.servicioAuth.verificarPermisoDeUsuarioPorRol(
          idRol,
          idMenu,
          accion,
        );
        return res;
      } catch (e) {
        throw e;
      }
    }
    console.log('Ejecutando estrategia');
    throw new HttpErrors[401](
      'No estas autenticado, No es posible realizar esta acción por falta de un token',
    );
  }
}