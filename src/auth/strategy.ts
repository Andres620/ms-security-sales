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
import {SeguridadUsuarioService} from '../services';

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

      let permiso = await this.repositorioRolMenu.findOne({
        where: {
          rolId: idRol,
          menuId: idMenu,
        },
      });

      let continuar: boolean = false;
      if (permiso) {
        switch (accion) {
          case 'guardar':
            continuar = permiso.guardar;
            break;
          case 'editar':
            continuar = permiso.editar;
            break;
          case 'listar':
            continuar = permiso.listar;
            break;
          case 'eliminar':
            continuar = permiso.eliminar;
            break;
          case 'descargar':
            continuar = permiso.descargar;
          default:
            throw new HttpErrors[401](
              'No es posible ejecutar la acción porque no existe',
            );
        }

        if (continuar) {
          let perfil: UserProfile = Object.assign({
            permitido: 'OK',
          });
          return perfil;
        } else {
          return undefined;
        }
      } else {
        throw new HttpErrors[401](
          'No tiene permisos para realizar esta acción',
        );
      }
    }
    console.log('Ejecutando estrategia');
    throw new HttpErrors[401](
      'No estas autenticado, No es posible realizar esta acción por falta de un token',
    );
  }
}
