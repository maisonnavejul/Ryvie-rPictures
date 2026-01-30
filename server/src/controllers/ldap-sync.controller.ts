import { Controller, Get } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { Endpoint, HistoryBuilder } from 'src/decorators';
import { UserRepository } from 'src/repositories/user.repository';
import { CryptoRepository } from 'src/repositories/crypto.repository';
import { LoggingRepository } from 'src/repositories/logging.repository';
import * as ldap from 'ldapjs';
import { promisify } from 'node:util';

interface LdapUser {
  uid: string;
  mail: string;
  cn: string[];
  givenName?: string;
  sn?: string;
  userPassword?: string;
  isAdmin: boolean;
}

@ApiTags('LDAP Sync')
@Controller('ldap')
export class LdapSyncController {
  private ldapClient: ldap.Client | null = null;

  constructor(
    private userRepository: UserRepository,
    private cryptoRepository: CryptoRepository,
    private logger: LoggingRepository,
  ) {}

  private getLdapClient(): ldap.Client {
    if (!this.ldapClient) {
      this.ldapClient = ldap.createClient({
        url: process.env.LDAP_URL || 'ldap://openldap:1389'
      });
    }
    return this.ldapClient;
  }

  private async bindLdap(): Promise<void> {
    const client = this.getLdapClient();
    const bind = promisify(client.bind.bind(client));
    await bind(
      process.env.LDAP_BIND_DN || 'cn=admin,dc=example,dc=org',
      process.env.LDAP_BIND_PASSWORD || 'adminpassword'
    );
  }

  private async isUserInGroup(userDn: string, groupCn: string): Promise<boolean> {
    const client = this.getLdapClient();
    const search = promisify<string, ldap.SearchOptions, ldap.SearchCallbackResponse>(client.search.bind(client));
    const results = await search(process.env.LDAP_USER_BASE_DN || 'ou=users,dc=example,dc=org', {
      scope: 'sub',
      filter: `(&(objectClass=groupOfNames)(cn=${groupCn})(member=${userDn}))`,
    });

    return new Promise((resolve) => {
      let found = false;
      
      results.on('searchEntry', () => {
        found = true;
      });

      results.on('end', () => {
        resolve(found);
      });

      results.on('error', () => {
        resolve(false);
      });
    });
  }

  private async getAllLdapUsers(): Promise<LdapUser[]> {
    const client = this.getLdapClient();
    const search = promisify<string, ldap.SearchOptions, ldap.SearchCallbackResponse>(client.search.bind(client));
    this.logger.log('Searching LDAP users...');
    
    const results = await search(process.env.LDAP_USER_BASE_DN || 'ou=users,dc=example,dc=org', {
      scope: 'sub',
      filter: process.env.LDAP_USER_FILTER || '(objectClass=inetOrgPerson)',
    });

    return new Promise((resolve, reject) => {
      const entries: LdapUser[] = [];
      const promises: Promise<void>[] = [];
      
      results.on('searchEntry', (entry: ldap.SearchEntry) => {
        const ldapUser = entry.pojo as any;
        
        if (!ldapUser.objectName || !ldapUser.attributes) {
          this.logger.warn(`Invalid LDAP user - DN: ${ldapUser.objectName}`);
          return;
        }

        const attributes: any = {};
        for (const attr of ldapUser.attributes) {
          attributes[attr.type] = attr.values;
        }

        const uidAttr = process.env.LDAP_UID_ATTRIBUTE || 'uid';
        const emailAttr = process.env.LDAP_EMAIL_ATTRIBUTE || 'mail';
        const nameAttr = process.env.LDAP_NAME_ATTRIBUTE || 'cn';
        const givenNameAttr = process.env.LDAP_GIVEN_NAME_ATTRIBUTE || 'givenName';
        const snAttr = process.env.LDAP_SN_ATTRIBUTE || 'sn';
        const passwordAttr = process.env.LDAP_PASSWORD_ATTRIBUTE || 'userPassword';

        if (!attributes[uidAttr] || !attributes[emailAttr] || !attributes[nameAttr]) {
          this.logger.warn(`LDAP user without uid, email or cn - DN: ${ldapUser.objectName}`);
          return;
        }

        const adminGroup = process.env.LDAP_ADMIN_GROUP || 'admins';
        const promise = this.isUserInGroup(ldapUser.objectName, adminGroup)
          .then(isAdmin => {
            entries.push({
              uid: attributes[uidAttr][0],
              mail: attributes[emailAttr][0],
              cn: attributes[nameAttr],
              givenName: attributes[givenNameAttr] ? attributes[givenNameAttr][0] : undefined,
              sn: attributes[snAttr] ? attributes[snAttr][0] : undefined,
              userPassword: attributes[passwordAttr] ? attributes[passwordAttr][0] : undefined,
              isAdmin
            });
            this.logger.log(`🔍 LDAP user loaded: ${attributes[uidAttr][0]} (${attributes[emailAttr][0]})`);
          });
        promises.push(promise);
      });

      results.on('error', (err: Error) => {
        this.logger.error('Error during LDAP search:', err);
        reject(err);
      });

      results.on('end', () => {
        void Promise.all(promises)
          .then(() => {
            this.logger.log(`Total LDAP users found: ${entries.length}`);
            resolve(entries);
          })
          .catch((error) => {
            reject(error);
          });
      });
    });
  }

  @Get('sync')
  @Endpoint({
    summary: 'Synchronize users from LDAP',
    description: 'Synchronize users from LDAP directory to Immich database. This is a public endpoint.',
    history: new HistoryBuilder().added('v1'),
  })
  async syncLdap() {
    this.logger.log('🔄 Starting LDAP users synchronization');
    try {
      await this.bindLdap();
      this.logger.log('✅ LDAP connection established');
      
      const ldapUsers = await this.getAllLdapUsers();
      this.logger.log(`📋 Found ${ldapUsers.length} users in LDAP`);
      
      let created = 0;
      let updated = 0;
      let deleted = 0;
      let errors = 0;

      // Build map of LDAP users by uid
      const ldapUserMap = new Map<string, typeof ldapUsers[0]>();
      for (const ldapUser of ldapUsers) {
        ldapUserMap.set(ldapUser.uid, ldapUser);
      }

      // Get all existing users from database
      const existingUsers = await this.userRepository.getList({ withDeleted: false });
      const existingUsersByStorageLabel = new Map();
      for (const user of existingUsers) {
        if (user.storageLabel) {
          existingUsersByStorageLabel.set(user.storageLabel, user);
        }
      }

      // Process LDAP users (create or update)
      for (const ldapUser of ldapUsers) {
        try {
          if (!ldapUser.userPassword) {
            this.logger.warn(`⚠️  No password for user ${ldapUser.uid} (${ldapUser.mail}), skipped`);
            continue;
          }

          const hashedPassword = await this.cryptoRepository.hashBcrypt(ldapUser.userPassword, 10);
          
          // Find user by storageLabel (uid) first, then by email for migration
          let existingUser = existingUsersByStorageLabel.get(ldapUser.uid);
          if (!existingUser) {
            // Fallback: search by email for users not yet migrated to LDAP uid
            existingUser = await this.userRepository.getByEmail(ldapUser.mail);
          }

          if (existingUser) {
            // Update existing user
            const updates: any = {};
            let hasChanges = false;

            // Migrate storageLabel if needed (for existing users without LDAP uid)
            if (existingUser.storageLabel !== ldapUser.uid) {
              updates.storageLabel = ldapUser.uid;
              hasChanges = true;
              this.logger.log(`🔄 StorageLabel migrated: ${existingUser.storageLabel || 'null'} → ${ldapUser.uid}`);
            }

            // Check email change
            if (existingUser.email !== ldapUser.mail) {
              updates.email = ldapUser.mail;
              hasChanges = true;
              this.logger.log(`📧 Email updated: ${ldapUser.uid} (${existingUser.email} → ${ldapUser.mail})`);
            }

            // Check admin status change - sync with LDAP group membership
            if (existingUser.isAdmin !== ldapUser.isAdmin) {
              updates.isAdmin = ldapUser.isAdmin;
              hasChanges = true;
              if (ldapUser.isAdmin) {
                this.logger.log(`👑 Admin promoted: ${ldapUser.uid}`);
              } else {
                this.logger.log(`👤 Admin demoted: ${ldapUser.uid}`);
              }
            }

            // Check name change
            const firstName = ldapUser.givenName || ldapUser.uid;
            const lastName = ldapUser.sn && ldapUser.sn !== firstName ? ldapUser.sn : '';
            const fullName = lastName ? `${firstName} ${lastName}` : firstName;
            
            if (existingUser.name !== fullName) {
              updates.name = fullName;
              hasChanges = true;
            }

            // Always update password
            updates.password = hashedPassword;
            hasChanges = true;

            if (hasChanges) {
              await this.userRepository.update(existingUser.id, updates);
              updated++;
            }
          } else {
            // Create new user
            const firstName = ldapUser.givenName || ldapUser.uid;
            const lastName = ldapUser.sn && ldapUser.sn !== firstName ? ldapUser.sn : '';
            const fullName = lastName ? `${firstName} ${lastName}` : firstName;

            await this.userRepository.create({
              isAdmin: ldapUser.isAdmin,
              email: ldapUser.mail,
              name: fullName,
              password: hashedPassword,
              storageLabel: ldapUser.uid,
              shouldChangePassword: false,
            });
            created++;
            this.logger.log(`🆕 Creating: ${ldapUser.uid} (${ldapUser.mail})`);
          }
        } catch (error) {
          errors++;
          this.logger.error(`❌ Error processing user ${ldapUser.uid}:`, error);
        }
      }

      // Delete users not in LDAP anymore
      // Only delete users with LDAP uid in storageLabel (not random UUIDs or null)
      for (const [storageLabel, user] of existingUsersByStorageLabel) {
        // Skip users with UUID-style storageLabel (not from LDAP)
        if (storageLabel.startsWith('user-') || !storageLabel) {
          continue;
        }
        
        if (!ldapUserMap.has(storageLabel)) {
          try {
            await this.userRepository.delete({ id: user.id }, false);
            deleted++;
            this.logger.log(`🗑️  Deleting: ${storageLabel} (${user.email})`);
          } catch (error) {
            errors++;
            this.logger.error(`❌ Error deleting user ${storageLabel}:`, error);
          }
        }
      }

      this.logger.log(`📊 Sync Summary: 🆕 ${created} created | 🔄 ${updated} updated | 🗑️ ${deleted} deleted | ❌ ${errors} errors`);
      return { created, updated, deleted, errors };
    } catch (error_) {
      const error = error_ as Error;
      this.logger.error(`❌ LDAP synchronization failed: ${error.message}`);
      throw error;
    }
  }
}
