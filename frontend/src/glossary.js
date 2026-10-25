export const glossary = {
  tenant: {
    en: { term: 'Tenant', definition: 'An isolated administrative boundary for one organization.', example: 'tenant-alpha has its own users, groups, roles and clients; tadmin cannot manage tenant-beta.' },
    fa: { term: 'تِننت (Tenant)', definition: 'مرز مدیریتی جداگانه برای یک سازمان است.', example: 'tenant-alpha کاربران، گروه‌ها، نقش‌ها و کلاینت‌های خودش را دارد و tadmin نمی‌تواند tenant-beta را مدیریت کند.' },
  },
  drift: {
    en: { term: 'Drift', definition: 'The actual Keycloak realm no longer matches the platform’s expected configuration.', example: 'If brute-force protection should be enabled but was changed directly in Keycloak, Check drift reports the difference without repairing it.' },
    fa: { term: 'ناهماهنگی (Drift)', definition: 'وضعیت واقعی Realm در Keycloak دیگر با تنظیمات موردانتظار پلتفرم یکسان نیست.', example: 'اگر حفاظت brute-force باید فعال باشد ولی مستقیماً در Keycloak غیرفعال شده باشد، Check drift اختلاف را گزارش می‌کند و چیزی را خودکار تغییر نمی‌دهد.' },
  },
  inSync: {
    en: { term: 'In sync', definition: 'The checked Keycloak configuration matches the platform’s expected managed state.', example: 'The ownership marker and required security settings match the approved tenant template.' },
    fa: { term: 'همگام (In sync)', definition: 'تنظیمات بررسی‌شده Keycloak با وضعیت مدیریت‌شده موردانتظار پلتفرم یکسان است.', example: 'نشان مالکیت و تنظیمات امنیتی الزامی با template تأییدشده تِننت مطابقت دارند.' },
  },
  approvedPilot: {
    en: { term: 'Approved for pilot', definition: 'The request is accepted for controlled pilot use; it is not production approval.', example: 'The tenant mapping may be provisioned for evaluation while production readiness conditions remain open.' },
    fa: { term: 'تأییدشده برای پایلوت (Approved for pilot)', definition: 'درخواست برای استفاده کنترل‌شده پایلوت پذیرفته شده، اما مجوز Production نیست.', example: 'Realm تِننت می‌تواند برای ارزیابی ساخته شود، درحالی‌که شروط آمادگی Production همچنان باز هستند.' },
  },
  provisioning: {
    en: { term: 'Provisioning', definition: 'Creating and configuring the tenant realm from the approved platform template.', example: 'After approval, the platform creates the Keycloak realm, baseline roles and required security settings.' },
    fa: { term: 'آماده‌سازی (Provisioning)', definition: 'ایجاد و پیکربندی Realm تِننت براساس template تأییدشده پلتفرم است.', example: 'پس از تأیید، پلتفرم Realm، نقش‌های پایه و تنظیمات امنیتی لازم را در Keycloak ایجاد می‌کند.' },
  },
  authorizationService: {
    en: { term: 'Authorization service', definition: 'The Phase 3 policy service that decides whether an authenticated principal may perform a business action.', example: 'Cerbos may decide whether a user can approve an invoice after the BFF has already verified identity and tenant boundaries.' },
    fa: { term: 'سرویس مجوزدهی (Authorization service)', definition: 'سرویس policy در Phase 3 است که تصمیم می‌گیرد کاربر احراز هویت‌شده اجازه انجام یک عملیات کسب‌وکار را دارد یا خیر.', example: 'بعد از کنترل هویت و مرز تِننت توسط BFF، سرویس Cerbos می‌تواند درباره اجازه تأیید یک فاکتور تصمیم بگیرد.' },
  },
  client: {
    en: { term: 'OAuth/OIDC client', definition: 'An application or machine identity registered to request authentication or tokens.', example: 'demo-app redirects a user to sign in; a confidential service client uses a secret for machine-to-machine access.' },
    fa: { term: 'کلاینت OAuth/OIDC', definition: 'برنامه یا هویت ماشینی ثبت‌شده‌ای است که احراز هویت یا token درخواست می‌کند.', example: 'demo-app کاربر را برای ورود هدایت می‌کند؛ یک کلاینت محرمانه با secret برای ارتباط ماشین‌به‌ماشین استفاده می‌شود.' },
  },
  effectiveAccess: {
    en: { term: 'Effective access', definition: 'Everything a user can currently do, together with every reason they hold that access.', example: 'Alice may hold tenant-admin through /administrators and another role directly; both reasons are shown.' },
    fa: { term: 'دسترسی مؤثر (Effective access)', definition: 'تمام دسترسی‌های فعلی کاربر همراه با همه دلایلی است که آن دسترسی‌ها را ایجاد کرده‌اند.', example: 'ممکن است Alice نقش tenant-admin را از گروه /administrators و نقش دیگری را مستقیم داشته باشد؛ هر دو دلیل نمایش داده می‌شوند.' },
  },
  requiredActions: {
    en: { term: 'Required actions', definition: 'Steps Keycloak forces the user to complete at the next sign-in.', example: 'After a temporary password reset, UPDATE_PASSWORD requires the user to choose a new password.' },
    fa: { term: 'اقدامات الزامی (Required actions)', definition: 'مراحلی هستند که Keycloak کاربر را در ورود بعدی مجبور به تکمیل آن‌ها می‌کند.', example: 'پس از تنظیم رمز موقت، UPDATE_PASSWORD کاربر را ملزم می‌کند رمز تازه‌ای انتخاب کند.' },
  },
  bff: {
    en: { term: 'BFF', definition: 'Backend for Frontend: the server boundary designed specifically for this UI.', example: 'The Vue UI calls the Spring Boot BFF; the BFF keeps tokens server-side and calls Keycloak safely.' },
    fa: { term: 'BFF (Backend for Frontend)', definition: 'backend اختصاصی همین رابط کاربری و مرز امنیتی مرورگر با سرویس‌های داخلی است.', example: 'Vue با BFF مبتنی بر Spring Boot ارتباط دارد؛ BFF tokenها را سمت سرور نگه می‌دارد و با Keycloak ارتباط امن برقرار می‌کند.' },
  },
}
