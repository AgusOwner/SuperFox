// ArgentGate: pide una key de KeyAuth antes de dejar usar la app.
#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

static NSString *const kName = @"Galaxy X";
static NSString *const kOwner = @"554yMP2JCV";
static NSString *const kSecret = @"50c9be481c75ef85fb7cdafac2e4ea9309281449db79c2fc7d10927d7c5d6e2b";
static NSString *const kVer = @"1.0";
static NSString *const kAPI = @"https://keyauth.win/api/1.3/";
static NSString *const kKeyStore = @"argent.gate.key";
static NSString *const kHwidStore = @"argent.keyauth.hwid";

static UIWindow *gGate;
static UITextField *gField;
static UILabel *gMsg;
static UIButton *gBtn;
static NSString *gSession;
static BOOL gValid;

static NSString *HWID(void) {
    NSUserDefaults *d = NSUserDefaults.standardUserDefaults;
    NSString *h = [d stringForKey:kHwidStore];
    if (!h) { h = NSUUID.UUID.UUIDString; [d setObject:h forKey:kHwidStore]; }
    return h;
}

// Nombre que se ve bajo el icono (lo que haya puesto el panel al editar la
// IPA). Si por lo que sea no está, cae a "App" en vez de un nombre fijo.
static NSString *AppDisplayName(void) {
    NSString *n = [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleDisplayName"];
    if (![n isKindOfClass:NSString.class] || !n.length) {
        n = [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleName"];
    }
    return (([n isKindOfClass:NSString.class] && n.length) ? n : @"App").uppercaseString;
}

// Color de acento para este gate: lo pone el panel al generar la IPA, guardado
// en una clave propia del Info.plist ("ArgentAccentColor", hex "#RRGGBB").
// Si no vino (o es inválido), se usa el rojo de siempre.
static UIColor *AccentColor(void) {
    id hex = [NSBundle.mainBundle objectForInfoDictionaryKey:@"ArgentAccentColor"];
    if ([hex isKindOfClass:NSString.class]) {
        NSString *h = [(NSString *)hex stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        if ([h hasPrefix:@"#"]) h = [h substringFromIndex:1];
        if (h.length == 6) {
            unsigned int v = 0;
            NSScanner *sc = [NSScanner scannerWithString:h];
            if ([sc scanHexInt:&v] && sc.isAtEnd) {
                return [UIColor colorWithRed:((v >> 16) & 0xFF) / 255.0
                                        green:((v >> 8) & 0xFF) / 255.0
                                         blue:(v & 0xFF) / 255.0
                                        alpha:1.0];
            }
        }
    }
    return [UIColor colorWithRed:0.86 green:0.1 blue:0.12 alpha:1];
}

// Botón de contacto opcional (Discord o WhatsApp). El panel guarda en el
// Info.plist "ArgentContactType" ("discord"/"whatsapp") y "ArgentContactURL"
// (enlace https). Si no viene la URL, no se muestra ningún botón.
static NSString *gContactURL;

static NSString *ContactURL(void) {
    id u = [NSBundle.mainBundle objectForInfoDictionaryKey:@"ArgentContactURL"];
    if ([u isKindOfClass:NSString.class] && [(NSString *)u hasPrefix:@"https://"]) return u;
    return nil;
}

static NSString *ContactTitle(void) {
    id t = [NSBundle.mainBundle objectForInfoDictionaryKey:@"ArgentContactType"];
    return [t isKindOfClass:NSString.class] && [(NSString *)t isEqualToString:@"whatsapp"] ? @"WHATSAPP" : @"DISCORD";
}

static NSString *Enc(NSString *s) {
    NSMutableCharacterSet *cs = [NSCharacterSet alphanumericCharacterSet].mutableCopy;
    [cs addCharactersInString:@"-._~"];
    return [s stringByAddingPercentEncodingWithAllowedCharacters:cs] ?: @"";
}

static void Post(NSDictionary *p, void (^done)(NSDictionary *json, NSString *err)) {
    NSMutableArray *parts = [NSMutableArray array];
    for (NSString *k in p) [parts addObject:[NSString stringWithFormat:@"%@=%@", k, Enc(p[k])]];
    NSMutableURLRequest *r = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:kAPI]];
    r.HTTPMethod = @"POST";
    r.timeoutInterval = 15;
    [r setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
    r.HTTPBody = [[parts componentsJoinedByString:@"&"] dataUsingEncoding:NSUTF8StringEncoding];
    [[NSURLSession.sharedSession dataTaskWithRequest:r completionHandler:^(NSData *d, NSURLResponse *resp, NSError *e) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (e || !d) { done(nil, @"Sin conexion"); return; }
            id j = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
            if (![j isKindOfClass:NSDictionary.class]) { done(nil, @"Respuesta invalida"); return; }
            done(j, nil);
        });
    }] resume];
}

// result: 0 valida, 1 rechazada (msg), 2 offline (msg)
static void Check(NSString *key, BOOL retry, void (^done)(int res, NSString *msg)) {
    void (^lic)(void) = ^{
        NSMutableDictionary *p = @{@"type": @"license", @"key": key, @"hwid": HWID(),
                                   @"name": kName, @"ownerid": kOwner}.mutableCopy;
        if (gSession) p[@"sessionid"] = gSession;
        Post(p, ^(NSDictionary *j, NSString *err) {
            if (!j) { done(2, err); return; }
            if ([j[@"success"] boolValue]) { done(0, nil); return; }
            NSString *m = [j[@"message"] isKindOfClass:NSString.class] ? j[@"message"] : @"Key invalida";
            if (!retry && [m.lowercaseString containsString:@"session"]) {
                gSession = nil; Check(key, YES, done); return;
            }
            done(1, m);
        });
    };
    if (gSession) { lic(); return; }
    Post(@{@"type": @"init", @"ver": kVer, @"hash": @"", @"name": kName,
           @"ownerid": kOwner, @"secret": kSecret}, ^(NSDictionary *j, NSString *err) {
        if (!j) { done(2, err); return; }
        if (![j[@"success"] boolValue]) { done(1, j[@"message"] ?: @"Init fallo"); return; }
        gSession = j[@"sessionid"];
        lic();
    });
}

@interface AGHandler : NSObject
+ (void)submit;
+ (void)recheck;
+ (void)contact;
@end

static void HideGate(void) { gGate.hidden = YES; gGate = nil; gValid = YES; }

static void ShowGate(NSString *note) {
    if (gGate) { gMsg.text = note; return; }
    UIWindowScene *scene = nil;
    for (UIScene *s in UIApplication.sharedApplication.connectedScenes)
        if ([s isKindOfClass:UIWindowScene.class]) { scene = (UIWindowScene *)s; break; }
    gGate = scene ? [[UIWindow alloc] initWithWindowScene:scene] : [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    gGate.windowLevel = UIWindowLevelAlert + 1000;
    gGate.backgroundColor = UIColor.blackColor;
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor colorWithWhite:0.04 alpha:1];
    UILabel *t = [UILabel new];
    t.text = AppDisplayName(); t.textColor = UIColor.whiteColor;
    t.font = [UIFont systemFontOfSize:30 weight:UIFontWeightBlack];
    t.textAlignment = NSTextAlignmentCenter;
    gField = [UITextField new];
    gField.placeholder = @"Pega tu licencia";
    gField.attributedPlaceholder = [[NSAttributedString alloc] initWithString:@"Pega tu licencia"
        attributes:@{NSForegroundColorAttributeName: [UIColor colorWithWhite:0.5 alpha:1]}];
    gField.textColor = UIColor.whiteColor;
    gField.backgroundColor = [UIColor colorWithWhite:0.12 alpha:1];
    gField.layer.cornerRadius = 12;
    gField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    gField.autocorrectionType = UITextAutocorrectionTypeNo;
    gField.leftView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 14, 10)];
    gField.leftViewMode = UITextFieldViewModeAlways;
    gBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [gBtn setTitle:@"Activar" forState:UIControlStateNormal];
    [gBtn setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    gBtn.titleLabel.font = [UIFont systemFontOfSize:17 weight:UIFontWeightBold];
    gBtn.backgroundColor = AccentColor();
    gBtn.layer.cornerRadius = 12;
    [gBtn addTarget:AGHandler.class action:@selector(submit) forControlEvents:UIControlEventTouchUpInside];
    gMsg = [UILabel new];
    gMsg.text = note; gMsg.textColor = [UIColor colorWithWhite:0.7 alpha:1];
    gMsg.font = [UIFont systemFontOfSize:13]; gMsg.numberOfLines = 0;
    gMsg.textAlignment = NSTextAlignmentCenter;
    // Logo arriba del nombre: el panel mete "ArgentGateLogo.png" dentro de la
    // IPA cuando se sube un logo. Si no está, el gate queda sin logo como antes.
    NSMutableArray *rows = [NSMutableArray arrayWithObjects:t, gField, gBtn, gMsg, nil];
    gContactURL = ContactURL();
    if (gContactURL) {
        UIColor *accent = AccentColor();
        UIButton *cb = [UIButton buttonWithType:UIButtonTypeSystem];
        [cb setTitle:ContactTitle() forState:UIControlStateNormal];
        [cb setTitleColor:accent forState:UIControlStateNormal];
        cb.titleLabel.font = [UIFont systemFontOfSize:16 weight:UIFontWeightHeavy];
        cb.backgroundColor = [UIColor colorWithWhite:0.08 alpha:1];
        cb.layer.cornerRadius = 12;
        cb.layer.borderWidth = 1;
        cb.layer.borderColor = [accent colorWithAlphaComponent:0.5].CGColor;
        [cb.heightAnchor constraintEqualToConstant:50].active = YES;
        [cb addTarget:AGHandler.class action:@selector(contact) forControlEvents:UIControlEventTouchUpInside];
        [rows insertObject:cb atIndex:3]; // debajo de "Activar", antes del mensaje
    }
    NSString *logoPath = [NSBundle.mainBundle pathForResource:@"ArgentGateLogo" ofType:@"png"];
    UIImage *logo = logoPath ? [UIImage imageWithContentsOfFile:logoPath] : nil;
    if (logo) {
        UIImageView *iv = [[UIImageView alloc] initWithImage:logo];
        iv.contentMode = UIViewContentModeScaleAspectFit;
        [iv.heightAnchor constraintEqualToConstant:110].active = YES;
        [rows insertObject:iv atIndex:0];
    }
    UIStackView *st = [[UIStackView alloc] initWithArrangedSubviews:rows];
    st.axis = UILayoutConstraintAxisVertical; st.spacing = 16;
    if (logo) [st setCustomSpacing:22 afterView:rows[0]];
    st.translatesAutoresizingMaskIntoConstraints = NO;
    [vc.view addSubview:st];
    [NSLayoutConstraint activateConstraints:@[
        [st.centerYAnchor constraintEqualToAnchor:vc.view.centerYAnchor constant:-40],
        [st.leadingAnchor constraintEqualToAnchor:vc.view.leadingAnchor constant:28],
        [st.trailingAnchor constraintEqualToAnchor:vc.view.trailingAnchor constant:-28],
        [gField.heightAnchor constraintEqualToConstant:50],
        [gBtn.heightAnchor constraintEqualToConstant:50]]];
    [vc.view addGestureRecognizer:[[UITapGestureRecognizer alloc] initWithTarget:vc.view action:@selector(endEditing:)]];
    gGate.rootViewController = vc;
    gGate.hidden = NO;
    [gGate makeKeyAndVisible];
}

@implementation AGHandler
+ (void)contact {
    NSURL *u = gContactURL ? [NSURL URLWithString:gContactURL] : nil;
    if (u) [UIApplication.sharedApplication openURL:u options:@{} completionHandler:nil];
}
+ (void)submit {
    NSString *k = [gField.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (!k.length) { gMsg.text = @"Escribe tu licencia."; return; }
    gBtn.enabled = NO; gMsg.text = @"Verificando...";
    Check(k, NO, ^(int res, NSString *m) {
        gBtn.enabled = YES;
        if (res == 0) {
            [NSUserDefaults.standardUserDefaults setObject:k forKey:kKeyStore];
            HideGate();
        } else gMsg.text = m ?: @"Key invalida";
    });
}
+ (void)recheck {
    NSString *k = [NSUserDefaults.standardUserDefaults stringForKey:kKeyStore];
    if (!k.length) { gValid = NO; ShowGate(@"Ingresa tu licencia para continuar."); return; }
    if (!gValid) ShowGate(@"Verificando licencia...");
    Check(k, NO, ^(int res, NSString *m) {
        if (res == 0) { if (gGate) HideGate(); gValid = YES; }
        else if (res == 1) {
            [NSUserDefaults.standardUserDefaults removeObjectForKey:kKeyStore];
            gValid = NO; ShowGate(m ?: @"Tu licencia ya no es valida.");
        } else {
            // Sin internet: si ya estaba validada en esta sesion no se bloquea.
            if (!gValid) ShowGate(@"Se necesita internet para verificar la licencia.");
        }
    });
}
@end

__attribute__((constructor))
static void ArgentGateInit(void) {
    NSNotificationCenter *nc = NSNotificationCenter.defaultCenter;
    [nc addObserverForName:UIApplicationDidBecomeActiveNotification object:nil
                     queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *n) {
        [AGHandler recheck];
    }];
}
