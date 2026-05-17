const fs = require('fs');

const schema = {
  User: ['id: Int (PK)', 'email: String (U)', 'provider: String', 'username: String?', 'passwordHash: String?', 'avatar: String?', 'otpCode: String?', 'otpExpires: DateTime?', 'resetPasswordToken: String?', 'resetPasswordExpires: DateTime?', 'oauthId: String?', 'oauthAccessToken: String?', 'oauthRefreshToken: String?', 'isVerified: Boolean', 'totpSecret: String?', 'totpEnabled: Boolean', 'role: Role', 'bannedAt: DateTime?', 'deletedAt: DateTime?', 'createdAt: DateTime'],
  UserSession: ['id: Int (PK)', 'userId: Int (FK)', 'userAgent: String', 'ipAddress: String', 'deviceOs: String?', 'deviceBrowser: String?', 'loginAt: DateTime', 'expiresAt: DateTime', 'createdAt: DateTime'],
  UserSetting: ['id: Int (PK)', 'userId: Int (FK/U)', 'themeMode: ThemeMode', 'notificationsEnabled: Boolean', 'createdAt: DateTime', 'updatedAt: DateTime'],
  MailBox: ['id: Int (PK)', 'userId: Int (FK)', 'provider: EmailProviders?', 'emailAddress: String?', 'displayName: String', 'isActive: Boolean', 'pushNotificationsEnabled: Boolean', 'lastSyncedAt: DateTime', 'createdAt: DateTime'],
  ImapConfig: ['id: Int (PK)', 'mailBoxId: Int (FK/U)', 'host: String', 'port: Int', 'secure: Boolean', 'authType: ImapAuthType', 'passwordEncrypted: String?', 'createdAt: DateTime'],
  SmtpConfig: ['id: Int (PK)', 'mailBoxId: Int (FK/U)', 'host: String', 'port: Int', 'secure: Boolean', 'authType: SmtpAuthType', 'passwordEncrypted: String?', 'createdAt: DateTime'],
  OauthToken: ['id: Int (PK)', 'mailBoxId: Int (FK/U)', 'provider: String', 'accessTokenEncrypted: String', 'refreshTokenEncrypted: String', 'expiresAt: DateTime', 'scope: String', 'createdAt: DateTime'],
  Folder: ['id: Int (PK)', 'mailBoxId: Int (FK)', 'name: String', 'type: FolderType', 'remoteId: String', 'createdAt: DateTime'],
  Email: ['id: Int (PK)', 'mailBoxId: Int (FK)', 'folderId: Int (FK)', 'messageId: String', 'subject: String', 'fromAddr: String', 'fromName: String?', 'toAddr: Json', 'ccAddr: Json?', 'bccAddr: Json?', 'bodyText: String?', 'bodyHtml: String?', 'isRead: Boolean', 'isFlagged: Boolean', 'isSpam: Boolean', 'isPhishing: Boolean', 'spamScore: Int', 'phishingScore: Int', 'malwareScore: Int?', 'malwareVerdict: String?', 'malwareSeverity: String?', 'aiReport: Json?', 'analysisStatus: AnalysisStatus', 'inReplyTo: String?', 'references: String?', 'receivedAt: DateTime', 'createdAt: DateTime'],
  EmailFlag: ['id: Int (PK)', 'emailId: Int (FK/U)', 'type: EmailFlagType', 'createdAt: DateTime'],
  Attachment: ['id: Int (PK)', 'emailId: Int (FK)', 'mimeType: String', 'filename: String?', 'size: Int', 'storagePath: String', 'createdAt: DateTime'],
  Notification: ['id: Int (PK)', 'userId: Int (FK)', 'type: NotificationType', 'title: String', 'message: String', 'isRead: Boolean', 'metadata: Json?', 'mailBoxId: Int? (FK)', 'emailId: Int? (FK)', 'createdAt: DateTime'],
  SyncLog: ['id: Int (PK)', 'mailBoxId: Int (FK)', 'status: SyncStatus', 'errorMessage: String?', 'syncedAt: DateTime'],
  AuditLog: ['id: Int (PK)', 'adminId: Int (FK)', 'action: String', 'targetType: AuditTargetType', 'targetId: Int?', 'details: Json?', 'createdAt: DateTime']
};

const allRelations = [
  { source: 'User', target: 'UserSession', label: '1:N', srcField: 'id', tgtField: 'userId' },
  { source: 'User', target: 'UserSetting', label: '1:1', srcField: 'id', tgtField: 'userId' },
  { source: 'User', target: 'MailBox', label: '1:N', srcField: 'id', tgtField: 'userId' },
  { source: 'User', target: 'Notification', label: '1:N', srcField: 'id', tgtField: 'userId' },
  { source: 'User', target: 'AuditLog', label: '1:N', srcField: 'id', tgtField: 'adminId' },
  { source: 'MailBox', target: 'ImapConfig', label: '1:1', srcField: 'id', tgtField: 'mailBoxId' },
  { source: 'MailBox', target: 'SmtpConfig', label: '1:1', srcField: 'id', tgtField: 'mailBoxId' },
  { source: 'MailBox', target: 'OauthToken', label: '1:1', srcField: 'id', tgtField: 'mailBoxId' },
  { source: 'MailBox', target: 'Folder', label: '1:N', srcField: 'id', tgtField: 'mailBoxId' },
  { source: 'MailBox', target: 'Email', label: '1:N', srcField: 'id', tgtField: 'mailBoxId' },
  { source: 'MailBox', target: 'SyncLog', label: '1:N', srcField: 'id', tgtField: 'mailBoxId' },
  { source: 'Folder', target: 'Email', label: '1:N', srcField: 'id', tgtField: 'folderId' },
  { source: 'Email', target: 'EmailFlag', label: '1:1', srcField: 'id', tgtField: 'emailId' },
  { source: 'Email', target: 'Attachment', label: '1:N', srcField: 'id', tgtField: 'emailId' },
  { source: 'MailBox', target: 'Notification', label: '1:N', srcField: 'id', tgtField: 'mailBoxId' },
  { source: 'Email', target: 'Notification', label: '1:N', srcField: 'id', tgtField: 'emailId' }
];

function generateDiagram(filename, title, includeTables) {
  let xml = `<mxfile host="Electron" agent="Antigravity AI" version="21.0.0" type="device">
  <diagram id="SecureMailSchema" name="${title}">
    <mxGraphModel dx="1412" dy="861" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="2000" pageHeight="2000" math="0" shadow="0">
      <root>
        <mxCell id="0" />
        <mxCell id="1" parent="0" />
`;

  let x = 40;
  let y = 40;
  let rowMaxHeight = 0;
  let col = 0;

  const filteredTables = Object.entries(schema).filter(([table]) => includeTables === null || includeTables.includes(table));
  const filteredRelations = allRelations.filter(rel => (includeTables === null) || (includeTables.includes(rel.source) && includeTables.includes(rel.target)));

  for (const [table, fields] of filteredTables) {
    const height = 26 + (fields.length * 26);
    xml += `        <!-- ${table} Table -->
        <mxCell id="${table}_table" parent="1" style="swimlane;fontStyle=0;childLayout=stackLayout;horizontal=1;startSize=26;horizontalStack=0;resizeParent=1;resizeParentMax=0;resizeLast=1;collapsible=1;marginBottom=0;html=1;" value="${table}" vertex="1">
          <mxGeometry height="${height}" width="250" x="${x}" y="${y}" as="geometry" />
        </mxCell>
`;
    
    fields.forEach((field, index) => {
      const yPos = 26 + (index * 26);
      const fieldId = `${table}_${field.split(':')[0].trim()}`;
      xml += `        <mxCell id="${fieldId}" parent="${table}_table" style="text;strokeColor=none;fillColor=none;align=left;verticalAlign=top;spacingLeft=4;spacingRight=4;overflow=hidden;rotatable=0;points=[[0,0.5],[1,0.5]];portConstraint=eastwest;whiteSpace=wrap;html=1;" value="+ ${field}" vertex="1">
          <mxGeometry height="26" width="250" y="${yPos}" as="geometry" />
        </mxCell>
`;
    });

    x += 320;
    rowMaxHeight = Math.max(rowMaxHeight, height);
    col++;
    if (col >= 3) {
      col = 0;
      x = 40;
      y += rowMaxHeight + 40;
      rowMaxHeight = 0;
    }
  }

  filteredRelations.forEach((rel, index) => {
    const sourceId = `${rel.source}_${rel.srcField}`;
    const targetId = `${rel.target}_${rel.tgtField}`;
    xml += `        <!-- Rel ${rel.source} -> ${rel.target} -->
        <mxCell id="rel_${index}" edge="1" parent="1" source="${sourceId}" target="${targetId}" value="${rel.label}" style="edgeStyle=orthogonalEdgeStyle;rounded=0;orthogonalLoop=1;jettySize=auto;html=1;exitX=1;exitY=0.5;exitDx=0;exitDy=0;entryX=0;entryY=0.5;entryDx=0;entryDy=0;">
          <mxGeometry relative="1" as="geometry" />
        </mxCell>
`;
  });

  xml += `      </root>
    </mxGraphModel>
  </diagram>
</mxfile>`;

  fs.writeFileSync('c:/Users/moham/projects/Securemail/SecureMail-Backend/docs/diagrams/' + filename, xml);
  console.log('Generated ' + filename);
}

// Full
generateDiagram('schema_erd.drawio', 'SecureMail ERD (Full)', null);

// User focused
generateDiagram('user_erd.drawio', 'User ERD', ['User', 'UserSession', 'UserSetting', 'MailBox', 'Notification', 'AuditLog']);

// MailBox focused
generateDiagram('mailbox_erd.drawio', 'MailBox ERD', ['MailBox', 'User', 'ImapConfig', 'SmtpConfig', 'OauthToken', 'Folder', 'Email', 'Notification', 'SyncLog']);

// Email focused
generateDiagram('email_erd.drawio', 'Email ERD', ['Email', 'MailBox', 'Folder', 'EmailFlag', 'Attachment', 'Notification']);
