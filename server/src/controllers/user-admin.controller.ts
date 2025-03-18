import { Body, Controller, Delete, Get, HttpCode, HttpStatus, Param, Post, Put, Query } from '@nestjs/common';
import { ApiTags, ApiOperation } from '@nestjs/swagger';
import { AuthDto } from 'src/dtos/auth.dto';
import { UserPreferencesResponseDto, UserPreferencesUpdateDto } from 'src/dtos/user-preferences.dto';
import {
  UserAdminCreateDto,
  UserAdminDeleteDto,
  UserAdminResponseDto,
  UserAdminSearchDto,
  UserAdminUpdateDto,
  mapUserAdmin,
} from 'src/dtos/user.dto';
import { Permission } from 'src/enum';
import { Auth, Authenticated, Public } from 'src/middleware/auth.guard';
import { UserAdminService } from 'src/services/user-admin.service';
import { UUIDParamDto } from 'src/validation';
import { AuthService } from 'src/services/auth.service';
import { SignUpDto } from 'src/dtos/auth.dto';
import { LoggingRepository } from 'src/repositories/logging.repository';
import { UserRepository } from 'src/repositories/user.repository';
import { CryptoRepository } from 'src/repositories/crypto.repository';
import { SALT_ROUNDS } from 'src/constants';
import { randomUUID } from 'crypto';
import * as ldap from 'ldapjs';
import { promisify } from 'util';
import { SearchEntryObject } from 'ldapjs';

interface LdapUser {
  mail: string;
  cn: string[];
  userPassword?: string;
}

@ApiTags('Users (admin)')
@Controller('admin/users')
export class UserAdminController {
  private ldapClient: ldap.Client;

  constructor(
    private service: UserAdminService,
    private authService: AuthService,
    private userRepository: UserRepository,
    private cryptoRepository: CryptoRepository,
    private logger: LoggingRepository,
  ) {
    this.ldapClient = ldap.createClient({
      url: 'ldap://172.20.0.1:389'
    });
  }

  private async bindLdap(): Promise<void> {
    const bind = promisify(this.ldapClient.bind.bind(this.ldapClient));
    await bind('cn=admin,dc=example,dc=org', 'adminpassword');
  }

  private async searchLdapUser(email: string): Promise<LdapUser | null> {
    const search = promisify<string, ldap.SearchOptions, ldap.SearchCallbackResponse>(this.ldapClient.search.bind(this.ldapClient));
    const results = await search('dc=example,dc=org', {
      scope: 'sub',
      filter: `(mail=${email})`
    });

    return new Promise((resolve, reject) => {
      const entries: LdapUser[] = [];
      
      results.on('searchEntry', (entry: ldap.SearchEntry) => {
        entries.push(entry.pojo as unknown as LdapUser);
      });

      results.on('error', (err: Error) => {
        reject(err);
      });

      results.on('end', () => {
        resolve(entries[0] || null);
      });
    });
  }

  private async getAllLdapUsers(): Promise<LdapUser[]> {
    const search = promisify<string, ldap.SearchOptions, ldap.SearchCallbackResponse>(this.ldapClient.search.bind(this.ldapClient));
    this.logger.log('Recherche des utilisateurs LDAP...');
    const results = await search('ou=users,dc=example,dc=org', {
      scope: 'sub',
      filter: '(objectClass=inetOrgPerson)',
      attributes: ['mail', 'cn', 'userPassword']
    });

    return new Promise((resolve, reject) => {
      const entries: LdapUser[] = [];
      
      results.on('searchEntry', (entry: ldap.SearchEntry) => {
        const ldapUser = entry.pojo as any;
        this.logger.log('Données LDAP brutes:', JSON.stringify(ldapUser, null, 2));
        
        // Extraire les attributs du format LDAP
        const attributes = ldapUser.attributes.reduce((acc: any, attr: any) => {
          acc[attr.type] = attr.values;
          return acc;
        }, {});

        this.logger.log('Attributs extraits:', JSON.stringify(attributes, null, 2));
        
        // Vérifier que les attributs requis sont présents
        if (!attributes.mail || !attributes.cn) {
          this.logger.warn(`Utilisateur LDAP invalide - mail: ${attributes.mail}, cn: ${attributes.cn}`);
          return;
        }

        entries.push({
          mail: attributes.mail[0],
          cn: attributes.cn,
          userPassword: attributes.userPassword ? attributes.userPassword[0] : undefined
        });
      });

      results.on('error', (err: Error) => {
        this.logger.error(`Erreur lors de la recherche LDAP: ${err.message}`);
        reject(err);
      });

      results.on('end', () => {
        this.logger.log(`Total des utilisateurs LDAP trouvés: ${entries.length}`);
        this.logger.log('Utilisateurs valides:', JSON.stringify(entries, null, 2));
        resolve(entries);
      });
    });
  }

  @Post('sync-ldap-users')
  @ApiOperation({ summary: 'Synchronise les utilisateurs depuis LDAP (Authentification requise)' })
  @Authenticated({ permission: Permission.ADMIN_USER_CREATE, admin: true })
  async syncLdapUsers() {
    return this.syncLdapUsersInternal();
  }

  @Public()
  @Get('sync-ldap')
  @ApiOperation({ summary: 'Synchronise les utilisateurs depuis LDAP (Public)' })
  async syncLdapPublic() {
    return this.syncLdapUsersInternal();
  }

  private async syncLdapUsersInternal() {
    this.logger.log('Starting LDAP users synchronization');
    try {
      await this.bindLdap();
      this.logger.log('Connexion LDAP établie');
      
      const ldapUsers = await this.getAllLdapUsers();
      this.logger.log(`Début de la synchronisation pour ${ldapUsers.length} utilisateurs`);
      
      let created = 0;
      let skipped = 0;

      for (const ldapUser of ldapUsers) {
        try {
          this.logger.log(`Traitement de l'utilisateur LDAP: ${ldapUser.mail}`);
          // Vérifier si l'utilisateur existe déjà
          const existingUser = await this.userRepository.getByEmail(ldapUser.mail);
          if (existingUser) {
            this.logger.log(`User ${ldapUser.mail} already exists, skipping`);
            skipped++;
            continue;
          }

          // Créer l'utilisateur
          const hashedPassword = await this.cryptoRepository.hashBcrypt(ldapUser.userPassword || 'changeme', SALT_ROUNDS);
          const storageLabel = `user-${randomUUID()}`;
          await this.userRepository.create({
            isAdmin: false,
            email: ldapUser.mail,
            name: ldapUser.cn[0],
            password: hashedPassword,
            storageLabel,
            shouldChangePassword: true, // Forcer le changement de mot de passe à la première connexion
          });
          created++;
          this.logger.log(`Created user account for ${ldapUser.mail}`);
        } catch (err) {
          const error = err as Error;
          this.logger.error(`Failed to create user ${ldapUser.mail}: ${error.message}`);
          skipped++;
        }
      }

      this.logger.log(`LDAP synchronization completed. Created: ${created}, Skipped: ${skipped}`);
      return { created, skipped };
    } catch (err) {
      const error = err as Error;
      this.logger.error(`LDAP synchronization failed: ${error.message}`);
      throw error;
    }
  }

  @Post('signup')
  async createAdmin(@Body() dto: SignUpDto): Promise<UserAdminResponseDto> {
    this.logger.log(`Attempting to create admin account with email: ${dto.email}`);
    try {
      const hashedPassword = await this.cryptoRepository.hashBcrypt(dto.password, SALT_ROUNDS);
      const storageLabel = `admin-${randomUUID()}`;
      const admin = await this.userRepository.create({
        isAdmin: true,
        email: dto.email,
        name: dto.name,
        password: hashedPassword,
        storageLabel,
      });
      this.logger.log(`Successfully created admin account for ${dto.email}`);
      return mapUserAdmin(admin);
    } catch (err) {
      const error = err as Error;
      this.logger.error(`Failed to create admin account: ${error.message}`);
      throw error;
    }
  }

  @Post('signup-user')
  async createUser(@Body() dto: SignUpDto): Promise<UserAdminResponseDto> {
    this.logger.log(`Attempting to create user account with email: ${dto.email}`);
    try {
      // Vérifier si l'utilisateur existe dans LDAP
      await this.bindLdap();
      const ldapUser = await this.searchLdapUser(dto.email);
      
      if (!ldapUser) {
        throw new Error('User not found in LDAP directory');
      }

      const hashedPassword = await this.cryptoRepository.hashBcrypt(dto.password, SALT_ROUNDS);
      const storageLabel = `user-${randomUUID()}`;
      const user = await this.userRepository.create({
        isAdmin: false,
        email: dto.email,
        name: ldapUser.cn[0] || dto.name,
        password: hashedPassword,
        storageLabel,
      });
      this.logger.log(`Successfully created user account for ${dto.email}`);
      return mapUserAdmin(user);
    } catch (err) {
      const error = err as Error;
      this.logger.error(`Failed to create user account: ${error.message}`);
      throw error;
    }
  }

  @Get()
  @ApiOperation({ summary: 'Liste tous les utilisateurs (Authentification requise)' })
  @Authenticated({ permission: Permission.ADMIN_USER_READ })
  async getAll(@Query() query: UserListFilter): Promise<UserAdminResponseDto[]> {
    const users = await this.userRepository.getList(query);
    return users.map(mapUserAdmin);
  }

  @Public()
  @Get('public-list')
  @ApiOperation({ summary: 'Liste tous les utilisateurs (Public)' })
  async getAllPublic(@Query() query: UserListFilter): Promise<UserAdminResponseDto[]> {
    const users = await this.userRepository.getList(query);
    return users.map(mapUserAdmin);
  }

  @Get()
  @Authenticated({ permission: Permission.ADMIN_USER_READ, admin: true })
  searchUsersAdmin(@Auth() auth: AuthDto, @Query() dto: UserAdminSearchDto): Promise<UserAdminResponseDto[]> {
    return this.service.search(auth, dto);
  }

  @Post()
  @Authenticated({ permission: Permission.ADMIN_USER_CREATE, admin: true })
  createUserAdmin(@Body() createUserDto: UserAdminCreateDto): Promise<UserAdminResponseDto> {
    return this.service.create(createUserDto);
  }

  @Get(':id')
  @Authenticated({ permission: Permission.ADMIN_USER_READ, admin: true })
  getUserAdmin(@Auth() auth: AuthDto, @Param() { id }: UUIDParamDto): Promise<UserAdminResponseDto> {
    return this.service.get(auth, id);
  }

  @Put(':id')
  @Authenticated({ permission: Permission.ADMIN_USER_UPDATE, admin: true })
  updateUserAdmin(
    @Auth() auth: AuthDto,
    @Param() { id }: UUIDParamDto,
    @Body() dto: UserAdminUpdateDto,
  ): Promise<UserAdminResponseDto> {
    return this.service.update(auth, id, dto);
  }

  @Delete(':id')
  @Authenticated({ permission: Permission.ADMIN_USER_DELETE, admin: true })
  deleteUserAdmin(
    @Auth() auth: AuthDto,
    @Param() { id }: UUIDParamDto,
    @Body() dto: UserAdminDeleteDto,
  ): Promise<UserAdminResponseDto> {
    return this.service.delete(auth, id, dto);
  }

  @Get(':id/preferences')
  @Authenticated({ permission: Permission.ADMIN_USER_READ, admin: true })
  getUserPreferencesAdmin(@Auth() auth: AuthDto, @Param() { id }: UUIDParamDto): Promise<UserPreferencesResponseDto> {
    return this.service.getPreferences(auth, id);
  }

  @Put(':id/preferences')
  @Authenticated({ permission: Permission.ADMIN_USER_UPDATE, admin: true })
  updateUserPreferencesAdmin(
    @Auth() auth: AuthDto,
    @Param() { id }: UUIDParamDto,
    @Body() dto: UserPreferencesUpdateDto,
  ): Promise<UserPreferencesResponseDto> {
    return this.service.updatePreferences(auth, id, dto);
  }

  @Post(':id/restore')
  @Authenticated({ permission: Permission.ADMIN_USER_DELETE, admin: true })
  @HttpCode(HttpStatus.OK)
  restoreUserAdmin(@Auth() auth: AuthDto, @Param() { id }: UUIDParamDto): Promise<UserAdminResponseDto> {
    return this.service.restore(auth, id);
  }
}
