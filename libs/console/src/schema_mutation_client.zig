//! Version 35 records the client address on every audited management mutation. Each
//! trigger source row carries the address bound by the storage thread from the request's
//! authorization block, so replicated statements stay deterministic. Rows the system writes
//! without a request (probe results, deliveries, command completion, bootstrap) stay NULL,
//! which readers show as not recorded. Trigger bodies repeat their version-34 text with the
//! column added; no historical audit row is reconstructed.
pub const sql =
    "ALTER TABLE console_users ADD COLUMN client_ip TEXT;" ++
    "ALTER TABLE console_tokens ADD COLUMN client_ip TEXT;" ++
    "ALTER TABLE console_policy_stage ADD COLUMN client_ip TEXT;" ++
    "ALTER TABLE console_policy_order_stage ADD COLUMN client_ip TEXT;" ++
    "ALTER TABLE console_policy_import_commit ADD COLUMN client_ip TEXT;" ++
    "ALTER TABLE console_reputation_stage ADD COLUMN client_ip TEXT;" ++
    "ALTER TABLE console_country_commit ADD COLUMN client_ip TEXT;" ++
    "ALTER TABLE console_inspection_stage ADD COLUMN client_ip TEXT;" ++
    "ALTER TABLE console_page_stage ADD COLUMN client_ip TEXT;" ++
    "ALTER TABLE console_settings ADD COLUMN client_ip TEXT;" ++
    "ALTER TABLE console_notifications ADD COLUMN client_ip TEXT;" ++
    "ALTER TABLE console_kiosk_grants ADD COLUMN client_ip TEXT;" ++
    "ALTER TABLE console_commands ADD COLUMN client_ip TEXT;" ++
    "ALTER TABLE console_geo_active ADD COLUMN client_ip TEXT;" ++
    "ALTER TABLE console_totp ADD COLUMN client_ip TEXT;" ++
    "ALTER TABLE console_password_rotation ADD COLUMN client_ip TEXT;" ++
    "DROP TRIGGER console_command_intent;" ++
    "CREATE TRIGGER console_command_intent AFTER INSERT ON console_commands BEGIN INSERT " ++
    "INTO console_audit(actor,actor_role,action,subject,target,recorded_at,after_summary," ++
    "client_ip) VALUES(NEW.actor,NEW.actor_role,'node.command.intent',NEW.node,NEW.id,NEW" ++
    ".requested_at,json_object('command',NEW.kind,'revision',NEW.expected_revision,'state" ++
    "','intent'),NEW.client_ip);END;" ++
    "DROP TRIGGER console_country_apply;" ++
    "CREATE TRIGGER console_country_apply AFTER INSERT ON console_country_commit BEGIN IN" ++
    "SERT INTO console_audit(actor,action,subject,recorded_at,target,actor_role,before_su" ++
    "mmary,after_summary,client_ip) VALUES(NEW.actor,'reputation.country',NEW.expected_re" ++
    "vision+1,NEW.recorded_at,NEW.country,NEW.actor_role,(SELECT json_object('count',COUN" ++
    "T(*),'sha256',MIN(geo_generation),'removed',COALESCE(SUM(CASE WHEN NOT EXISTS(SELECT" ++
    " 1 FROM console_country_stage c WHERE c.digest=NEW.digest AND c.prefix=r.ip_or_cidr)" ++
    " THEN 1 ELSE 0 END),0)) FROM ip_reputation r WHERE source='console:country:'||NEW.co" ++
    "untry),json_object('count',NEW.count,'score',NEW.score,'expires',NEW.banned_until,'s" ++
    "ha256',NEW.geo_generation),NEW.client_ip);DELETE FROM ip_reputation WHERE source='co" ++
    "nsole:country:'||NEW.country AND NOT EXISTS (SELECT 1 FROM console_country_stage c W" ++
    "HERE c.digest=NEW.digest AND c.prefix=ip_reputation.ip_or_cidr);INSERT INTO ip_reput" ++
    "ation(ip_or_cidr,reputation_score,banned_until,trigger_rule,hits,last_seen,source,no" ++
    "te,geo_generation) SELECT prefix,NEW.score,NEW.banned_until,'console',0,NEW.recorded" ++
    "_at,'console:country:'||NEW.country,'',NEW.geo_generation FROM console_country_stage" ++
    " WHERE digest=NEW.digest ORDER BY ordinal ON CONFLICT(ip_or_cidr) DO UPDATE SET repu" ++
    "tation_score=excluded.reputation_score,banned_until=excluded.banned_until,trigger_ru" ++
    "le='console',last_seen=excluded.last_seen,source=excluded.source,note='',geo_generat" ++
    "ion=excluded.geo_generation;DELETE FROM console_country_stage WHERE digest=NEW.diges" ++
    "t;UPDATE sibuna_meta SET value=NEW.expected_revision+1 WHERE key='policy_version';DE" ++
    "LETE FROM console_country_commit WHERE id=NEW.id; END;" ++
    "DROP TRIGGER console_geo_activated;" ++
    "CREATE TRIGGER console_geo_activated AFTER UPDATE ON console_geo_active BEGIN INSERT" ++
    " INTO console_audit(actor,action,subject,recorded_at,client_ip) VALUES(NEW.actor,'ge" ++
    "oip.activate',NEW.revision,NEW.loaded_at,NEW.client_ip); END;" ++
    "DROP TRIGGER console_inspection_commit;" ++
    "CREATE TRIGGER console_inspection_commit AFTER INSERT ON console_inspection_stage BE" ++
    "GIN INSERT INTO policy_inspection VALUES(1,NEW.path_traversal,NEW.sqli,NEW.xss,NEW.r" ++
    "ce) ON CONFLICT(id) DO UPDATE SET path_traversal=excluded.path_traversal,sqli=exclud" ++
    "ed.sqli,xss=excluded.xss,rce=excluded.rce;INSERT INTO console_inspection_history VAL" ++
    "UES(NEW.expected_revision+1,NEW.actor,NEW.recorded_at,NEW.document,NEW.previous_docu" ++
    "ment);INSERT INTO console_audit(actor,action,subject,recorded_at,target,actor_role,b" ++
    "efore_summary,after_summary,client_ip) VALUES(NEW.actor,'inspection.edit',NEW.expect" ++
    "ed_revision+1,NEW.recorded_at,'inspection',NEW.actor_role,NEW.previous_document,NEW." ++
    "document,NEW.client_ip);DELETE FROM console_inspection_stage WHERE id=NEW.id; END;" ++
    "DROP TRIGGER console_kiosk_exchanged;" ++
    "CREATE TRIGGER console_kiosk_exchanged AFTER UPDATE OF consumed_at ON console_kiosk_" ++
    "grants WHEN NEW.consumed_at IS NOT NULL BEGIN INSERT INTO console_audit(actor,action" ++
    ",subject,recorded_at,client_ip) VALUES(NEW.user_id,'kiosk.exchange',NEW.user_id,NEW." ++
    "consumed_at,NEW.client_ip); END;" ++
    "DROP TRIGGER console_kiosk_granted;" ++
    "CREATE TRIGGER console_kiosk_granted AFTER INSERT ON console_kiosk_grants BEGIN INSE" ++
    "RT INTO console_audit(actor,action,subject,target,recorded_at,client_ip) VALUES(NEW." ++
    "user_id,'kiosk.grant',NEW.user_id,NEW.label,NEW.created_at,NEW.client_ip); END;" ++
    "DROP TRIGGER console_notification_changed;" ++
    "CREATE TRIGGER console_notification_changed AFTER UPDATE OF kind,transport,label,tar" ++
    "get,events,cooldown_seconds,enabled,secret_envelope ON console_notifications BEGIN I" ++
    "NSERT INTO console_audit(actor,actor_role,action,subject,target,recorded_at,before_s" ++
    "ummary,after_summary,client_ip) VALUES(NEW.modified_by,'admin','notification.change'" ++
    ",NEW.id,NEW.label,NEW.modified_at,json_object('kind',OLD.kind,'transport',OLD.transp" ++
    "ort,'events',OLD.events,'cooldown',OLD.cooldown_seconds,'enabled',OLD.enabled,'host'" ++
    ",OLD.target_host,'secret',CASE WHEN OLD.secret_envelope IS NULL THEN 'none' ELSE 'se" ++
    "t' END),json_object('kind',NEW.kind,'transport',NEW.transport,'events',NEW.events,'c" ++
    "ooldown',NEW.cooldown_seconds,'enabled',NEW.enabled,'host',NEW.target_host,'secret'," ++
    "CASE WHEN NEW.secret_envelope IS NULL THEN 'none' ELSE 'set' END),NEW.client_ip); EN" ++
    "D;" ++
    "DROP TRIGGER console_notification_created;" ++
    "CREATE TRIGGER console_notification_created AFTER INSERT ON console_notifications BE" ++
    "GIN INSERT INTO console_audit(actor,actor_role,action,subject,target,recorded_at,aft" ++
    "er_summary,client_ip) VALUES(NEW.created_by,'admin','notification.create',NEW.id,NEW" ++
    ".label,NEW.created_at,json_object('kind',NEW.kind,'transport',NEW.transport,'events'" ++
    ",NEW.events,'cooldown',NEW.cooldown_seconds,'enabled',NEW.enabled,'host',NEW.target_" ++
    "host,'secret',CASE WHEN NEW.secret_envelope IS NULL THEN 'none' ELSE 'set' END),NEW." ++
    "client_ip); END;" ++
    "DROP TRIGGER console_notification_removed;" ++
    "CREATE TRIGGER console_notification_removed AFTER DELETE ON console_notifications BE" ++
    "GIN INSERT INTO console_audit(actor,actor_role,action,subject,target,recorded_at,bef" ++
    "ore_summary,client_ip) VALUES(OLD.modified_by,'admin','notification.remove',OLD.id,O" ++
    "LD.label,OLD.modified_at,json_object('kind',OLD.kind,'host',OLD.target_host),OLD.cli" ++
    "ent_ip); END;" ++
    "DROP TRIGGER console_page_commit;" ++
    "CREATE TRIGGER console_page_commit AFTER INSERT ON console_page_stage BEGIN INSERT I" ++
    "NTO console_pages(kind,html,sha256,revision,updated_at,updated_by) SELECT NEW.kind,N" ++
    "EW.html,NEW.sha256,NEW.expected_revision+1,NEW.recorded_at,NEW.actor WHERE NEW.reset" ++
    "=0 ON CONFLICT(kind) DO UPDATE SET html=excluded.html,sha256=excluded.sha256,revisio" ++
    "n=excluded.revision,updated_at=excluded.updated_at,updated_by=excluded.updated_by;DE" ++
    "LETE FROM console_pages WHERE kind=NEW.kind AND NEW.reset=1;INSERT INTO console_audi" ++
    "t(actor,actor_role,action,subject,target,recorded_at,before_summary,after_summary,cl" ++
    "ient_ip) VALUES(NEW.actor,NEW.actor_role,CASE WHEN NEW.reset=1 THEN 'page.reset' ELS" ++
    "E 'page.edit' END,NEW.expected_revision+1,NEW.kind,NEW.recorded_at,CASE WHEN NEW.pre" ++
    "vious_sha256 IS NULL THEN NULL ELSE json_object('sha256',NEW.previous_sha256,'bytes'" ++
    ",NEW.previous_bytes) END,CASE WHEN NEW.reset=1 THEN NULL ELSE json_object('sha256',N" ++
    "EW.sha256,'bytes',NEW.bytes) END,NEW.client_ip);UPDATE sibuna_meta SET value=CAST(va" ++
    "lue AS INTEGER)+1 WHERE key='policy_version';DELETE FROM console_page_stage WHERE id" ++
    "=NEW.id; END;" ++
    "DROP TRIGGER console_policy_commit;" ++
    "CREATE TRIGGER console_policy_commit AFTER INSERT ON console_policy_stage BEGIN INSE" ++
    "RT INTO console_policy_history SELECT NEW.policy_id,NEW.expected_revision,0,NEW.reco" ++
    "rded_at,NEW.previous_document,'baseline' WHERE NEW.previous_document IS NOT NULL AND" ++
    " NOT EXISTS(SELECT 1 FROM console_policy_history WHERE policy_id=NEW.policy_id);INSE" ++
    "RT INTO policies(id,name,priority,enabled,path_pattern,ua_pattern,action,difficulty," ++
    "algorithm,weight,header_matchers,cidr_matchers,created_at,updated_at,limit_config) V" ++
    "ALUES(NEW.policy_id,NEW.name,NEW.priority,NEW.enabled,NEW.path_pattern,NEW.ua_patter" ++
    "n,NEW.action,NEW.difficulty,NEW.algorithm,NEW.weight,NEW.header_matchers,NEW.cidr_ma" ++
    "tchers,NEW.recorded_at,NEW.recorded_at,NEW.limit_config) ON CONFLICT(id) DO UPDATE S" ++
    "ET name=excluded.name,priority=excluded.priority,enabled=excluded.enabled,path_patte" ++
    "rn=excluded.path_pattern,ua_pattern=excluded.ua_pattern,action=excluded.action,diffi" ++
    "culty=excluded.difficulty,algorithm=excluded.algorithm,weight=excluded.weight,header" ++
    "_matchers=excluded.header_matchers,cidr_matchers=excluded.cidr_matchers,updated_at=e" ++
    "xcluded.updated_at,limit_config=excluded.limit_config;INSERT INTO console_policy_his" ++
    "tory VALUES(NEW.policy_id,NEW.expected_revision+1,NEW.actor,NEW.recorded_at,NEW.docu" ++
    "ment,'edit');INSERT INTO console_audit(actor,action,subject,recorded_at,target,actor" ++
    "_role,before_summary,after_summary,client_ip) VALUES(NEW.actor,'policy.edit',NEW.exp" ++
    "ected_revision+1,NEW.recorded_at,NEW.policy_id,NEW.actor_role,CASE WHEN NEW.previous" ++
    "_document IS NULL THEN NULL ELSE json_object('action',json_extract(NEW.previous_docu" ++
    "ment,'$.action'),'enabled',COALESCE(json_extract(NEW.previous_document,'$.enabled')," ++
    "1),'priority',COALESCE(json_extract(NEW.previous_document,'$.priority'),100),'diffic" ++
    "ulty',json_extract(NEW.previous_document,'$.difficulty'),'algorithm',json_extract(NE" ++
    "W.previous_document,'$.algorithm'),'weight',COALESCE(json_extract(NEW.previous_docum" ++
    "ent,'$.weight'),0),'rate',json_extract(NEW.previous_document,'$.limits.rate'),'windo" ++
    "w_seconds',json_extract(NEW.previous_document,'$.limits.window_seconds'),'ban_second" ++
    "s',json_extract(NEW.previous_document,'$.limits.ban_seconds'),'selectors_redacted',C" ++
    "ASE WHEN json_extract(NEW.previous_document,'$.path') IS NOT NULL OR json_extract(NE" ++
    "W.previous_document,'$.user_agent') IS NOT NULL OR EXISTS(SELECT 1 FROM json_each(NE" ++
    "W.previous_document,'$.headers')) OR EXISTS(SELECT 1 FROM json_each(NEW.previous_doc" ++
    "ument,'$.cidrs')) THEN 1 ELSE 0 END) END,json_object('action',json_extract(NEW.docum" ++
    "ent,'$.action'),'enabled',COALESCE(json_extract(NEW.document,'$.enabled'),1),'priori" ++
    "ty',COALESCE(json_extract(NEW.document,'$.priority'),100),'difficulty',json_extract(" ++
    "NEW.document,'$.difficulty'),'algorithm',json_extract(NEW.document,'$.algorithm'),'w" ++
    "eight',COALESCE(json_extract(NEW.document,'$.weight'),0),'rate',json_extract(NEW.doc" ++
    "ument,'$.limits.rate'),'window_seconds',json_extract(NEW.document,'$.limits.window_s" ++
    "econds'),'ban_seconds',json_extract(NEW.document,'$.limits.ban_seconds'),'selectors_" ++
    "redacted',CASE WHEN json_extract(NEW.document,'$.path') IS NOT NULL OR json_extract(" ++
    "NEW.document,'$.user_agent') IS NOT NULL OR EXISTS(SELECT 1 FROM json_each(NEW.docum" ++
    "ent,'$.headers')) OR EXISTS(SELECT 1 FROM json_each(NEW.document,'$.cidrs')) THEN 1 " ++
    "ELSE 0 END),NEW.client_ip);DELETE FROM console_policy_stage WHERE id=NEW.id; END;" ++
    "DROP TRIGGER console_policy_import_apply;" ++
    "CREATE TRIGGER console_policy_import_apply AFTER INSERT ON console_policy_import_com" ++
    "mit BEGIN DELETE FROM policies;INSERT INTO policies(id,name,priority,enabled,path_pa" ++
    "ttern,ua_pattern,action,difficulty,algorithm,weight,header_matchers,cidr_matchers,cr" ++
    "eated_at,updated_at,limit_config) SELECT policy_id,name,priority,enabled,path_patter" ++
    "n,ua_pattern,action,difficulty,algorithm,weight,header_matchers,cidr_matchers,NEW.re" ++
    "corded_at,NEW.recorded_at,limit_config FROM console_policy_import_stage WHERE digest" ++
    "=NEW.digest ORDER BY ordinal;INSERT INTO console_policy_history SELECT policy_id,NEW" ++
    ".expected_revision+1,NEW.actor,NEW.recorded_at,document,'edit' FROM console_policy_i" ++
    "mport_stage WHERE digest=NEW.digest;INSERT INTO console_audit(actor,action,subject,r" ++
    "ecorded_at,target,actor_role,after_summary,client_ip) VALUES(NEW.actor,'policy.impor" ++
    "t',NEW.expected_revision+1,NEW.recorded_at,NEW.digest,NEW.actor_role,json_object('co" ++
    "unt',NEW.count,'sha256',NEW.digest),NEW.client_ip);DELETE FROM console_policy_import" ++
    "_stage WHERE digest=NEW.digest;UPDATE sibuna_meta SET value=NEW.expected_revision+1 " ++
    "WHERE key='policy_version';DELETE FROM console_policy_import_commit WHERE id=NEW.id;" ++
    " END;" ++
    "DROP TRIGGER console_policy_order_commit;" ++
    "CREATE TRIGGER console_policy_order_commit AFTER INSERT ON console_policy_order_stag" ++
    "e BEGIN UPDATE policies SET priority=NEW.priority,updated_at=NEW.recorded_at WHERE i" ++
    "d=NEW.policy_id;UPDATE policies SET priority=NEW.other_priority,updated_at=NEW.recor" ++
    "ded_at WHERE id=NEW.other_id;INSERT INTO console_policy_history VALUES(NEW.policy_id" ++
    ",NEW.expected_revision+1,NEW.actor,NEW.recorded_at,NEW.document,'edit');INSERT INTO " ++
    "console_policy_history VALUES(NEW.other_id,NEW.expected_revision+1,NEW.actor,NEW.rec" ++
    "orded_at,NEW.other_document,'edit');INSERT INTO console_audit(actor,action,subject,r" ++
    "ecorded_at,target,actor_role,after_summary,client_ip) VALUES(NEW.actor,'policy.order" ++
    "',NEW.expected_revision+1,NEW.recorded_at,NEW.policy_id,NEW.actor_role,json_object('" ++
    "priority',NEW.priority),NEW.client_ip);UPDATE sibuna_meta SET value=NEW.expected_rev" ++
    "ision+1 WHERE key='policy_version';DELETE FROM console_policy_order_stage WHERE id=N" ++
    "EW.id; END;" ++
    "DROP TRIGGER console_reputation_commit;" ++
    "CREATE TRIGGER console_reputation_commit AFTER INSERT ON console_reputation_stage BE" ++
    "GIN DELETE FROM ip_reputation WHERE ip_or_cidr=NEW.prefix AND NEW.remove=1;INSERT IN" ++
    "TO ip_reputation(ip_or_cidr,reputation_score,banned_until,trigger_rule,hits,last_see" ++
    "n,source,note) SELECT NEW.prefix,NEW.score,NEW.banned_until,'console',0,NEW.recorded" ++
    "_at,NEW.source,NEW.note WHERE NEW.remove=0 ON CONFLICT(ip_or_cidr) DO UPDATE SET rep" ++
    "utation_score=excluded.reputation_score,banned_until=excluded.banned_until,trigger_r" ++
    "ule='console',last_seen=excluded.last_seen,source=excluded.source,note=excluded.note" ++
    ",geo_generation=NULL;INSERT INTO console_audit(actor,action,subject,recorded_at,targ" ++
    "et,actor_role,after_summary,client_ip) VALUES(NEW.actor,CASE WHEN NEW.remove=1 THEN " ++
    "'reputation.remove' ELSE 'reputation.edit' END,NEW.expected_revision+1,NEW.recorded_" ++
    "at,NEW.prefix,NEW.actor_role,CASE WHEN NEW.remove=1 THEN NULL ELSE json_object('scor" ++
    "e',NEW.score,'expires',NEW.banned_until) END,NEW.client_ip);UPDATE sibuna_meta SET v" ++
    "alue=NEW.expected_revision+1 WHERE key='policy_version';DELETE FROM console_reputati" ++
    "on_stage WHERE id=NEW.id; END;" ++
    "DROP TRIGGER console_setting_changed;" ++
    "CREATE TRIGGER console_setting_changed AFTER INSERT ON console_settings BEGIN INSERT" ++
    " INTO console_audit(actor,actor_role,action,subject,target,recorded_at,after_summary" ++
    ",client_ip) VALUES(NEW.updated_by,'admin','setting.change',NEW.revision,NEW.key,NEW." ++
    "updated_at,json_object('value',NEW.value),NEW.client_ip); END;" ++
    "DROP TRIGGER console_setting_updated;" ++
    "CREATE TRIGGER console_setting_updated AFTER UPDATE ON console_settings BEGIN INSERT" ++
    " INTO console_audit(actor,actor_role,action,subject,target,recorded_at,before_summar" ++
    "y,after_summary,client_ip) VALUES(NEW.updated_by,'admin','setting.change',NEW.revisi" ++
    "on,NEW.key,NEW.updated_at,json_object('value',OLD.value),json_object('value',NEW.val" ++
    "ue),NEW.client_ip); END;" ++
    "DROP TRIGGER console_token_changed;" ++
    "CREATE TRIGGER console_token_changed AFTER UPDATE ON console_tokens BEGIN DELETE FRO" ++
    "M console_sessions WHERE token_id=NEW.id;INSERT INTO console_audit(actor,action,subj" ++
    "ect,recorded_at,actor_role,before_summary,after_summary,client_ip) VALUES(NEW.modifi" ++
    "ed_by,CASE WHEN NEW.remove_requested=1 THEN 'token.remove' ELSE 'token.revoke' END,N" ++
    "EW.id,NEW.modified_at,'admin',json_object('label',OLD.label,'role',OLD.role,'scopes'" ++
    ",OLD.scopes,'expires',OLD.expires_at,'disabled',OLD.disabled,'revision',OLD.revision" ++
    "),json_object('label',NEW.label,'role',NEW.role,'scopes',NEW.scopes,'expires',NEW.ex" ++
    "pires_at,'disabled',NEW.disabled,'revision',NEW.revision),NEW.client_ip);DELETE FROM" ++
    " console_tokens WHERE id=NEW.id AND remove_requested=1; END;" ++
    "DROP TRIGGER console_token_created;" ++
    "CREATE TRIGGER console_token_created AFTER INSERT ON console_tokens BEGIN INSERT INT" ++
    "O console_sessions(digest,user_id,revision,csrf_digest,created_at,expires,idle_expir" ++
    "es,token_id) VALUES(NEW.digest,NEW.created_by,NEW.auth_revision,printf('%064d',0),NE" ++
    "W.created_at,COALESCE(NEW.expires_at,9223372036854775807),COALESCE(NEW.expires_at,92" ++
    "23372036854775807),NEW.id);INSERT INTO console_audit(actor,action,subject,recorded_a" ++
    "t,actor_role,after_summary,client_ip) VALUES(NEW.created_by,'token.create',NEW.id,NE" ++
    "W.created_at,'admin',json_object('label',NEW.label,'role',NEW.role,'scopes',NEW.scop" ++
    "es,'expires',NEW.expires_at,'disabled',NEW.disabled,'revision',NEW.revision),NEW.cli" ++
    "ent_ip); END;" ++
    "DROP TRIGGER console_totp_enabled;" ++
    "CREATE TRIGGER console_totp_enabled AFTER UPDATE ON console_totp WHEN NEW.enabled=1 " ++
    "AND OLD.enabled=0 BEGIN UPDATE console_users SET revision=revision+1,modified_by=id," ++
    "modified_at=NEW.modified_at,client_ip=NEW.client_ip WHERE id=NEW.user_id;INSERT INTO" ++
    " console_audit(actor,action,subject,recorded_at,client_ip) VALUES(NEW.user_id,'totp." ++
    "enable',NEW.user_id,NEW.modified_at,NEW.client_ip); END;" ++
    "DROP TRIGGER console_user_created;" ++
    "CREATE TRIGGER console_user_created AFTER INSERT ON console_users BEGIN INSERT INTO " ++
    "console_audit(actor,action,subject,recorded_at,actor_role,after_summary,client_ip) V" ++
    "ALUES(NEW.modified_by,'user.create',NEW.id,NEW.modified_at,(SELECT role FROM console" ++
    "_users WHERE id=NEW.modified_by),json_object('username',NEW.username,'role',NEW.role" ++
    ",'disabled',NEW.disabled,'must_change',NEW.must_change,'revision',NEW.revision),NEW." ++
    "client_ip); END;" ++
    "DROP TRIGGER console_user_updated;" ++
    "CREATE TRIGGER console_user_updated AFTER UPDATE ON console_users BEGIN INSERT INTO " ++
    "console_audit(actor,action,subject,recorded_at,actor_role,before_summary,after_summa" ++
    "ry,client_ip) VALUES(NEW.modified_by,CASE WHEN OLD.disabled!=NEW.disabled THEN CASE " ++
    "WHEN NEW.disabled=1 THEN 'user.disable' ELSE 'user.enable' END WHEN OLD.role!=NEW.ro" ++
    "le THEN 'user.role' WHEN OLD.password_hash!=NEW.password_hash THEN CASE WHEN NEW.mus" ++
    "t_change=1 THEN 'user.password_reset' ELSE 'user.password_change' END ELSE 'user.rev" ++
    "oke' END,NEW.id,NEW.modified_at,(SELECT role FROM console_users WHERE id=NEW.modifie" ++
    "d_by),json_object('username',OLD.username,'role',OLD.role,'disabled',OLD.disabled,'m" ++
    "ust_change',OLD.must_change,'revision',OLD.revision),json_object('username',NEW.user" ++
    "name,'role',NEW.role,'disabled',NEW.disabled,'must_change',NEW.must_change,'revision" ++
    "',NEW.revision),NEW.client_ip);DELETE FROM console_sessions WHERE user_id=NEW.id; EN" ++
    "D;" ++
    "DROP TRIGGER console_password_rotated;" ++
    "CREATE TRIGGER console_password_rotated AFTER INSERT ON console_password_rotation BE" ++
    "GIN UPDATE console_users SET password_hash=NEW.password_hash,revision=revision+1,mus" ++
    "t_change=0,password_expires=0,modified_at=NEW.recorded_at,modified_by=id,client_ip=N" ++
    "EW.client_ip WHERE id=NEW.user_id;INSERT INTO console_sessions(digest,user_id,revisi" ++
    "on,csrf_digest,created_at,expires,idle_expires,client_ip) SELECT NEW.digest,id,revis" ++
    "ion,NEW.csrf_digest,NEW.recorded_at,NEW.recorded_at+43200,NEW.recorded_at+1800,NEW.c" ++
    "lient_ip FROM console_users WHERE id=NEW.user_id;DELETE FROM console_password_rotati" ++
    "on WHERE id=NEW.id; END;" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=35));" ++
    "INSERT INTO console_schema VALUES(35);";
