import { Module } from '@nestjs/common';
import { EmailAccountsController } from './email-accounts.controller';
import { EmailAccountsService } from './email-accounts.service';

@Module({
  controllers: [EmailAccountsController],
  providers: [EmailAccountsService]
})
export class EmailAccountsModule {}
