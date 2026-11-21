#import "InfoViewController.h"
#import <LinkPresentation/LPLinkMetadata.h>

// ==================== EDIT HERE ====================
static NSString * const kAuthorInitials   = @"RE";  // твои инициалы
static NSString * const kTelegramGroup    = @"https://t.me/your_group";   // ссылка на группу
static NSString * const kTelegramChannel  = @"https://t.me/your_channel"; // ссылка на канал
static NSString * const kContactTelegram  = @"https://t.me/your_username"; // связь с тобой
static NSString * const kProjectVersion   = @"0.1.0";
// ===================================================

@interface InfoViewController ()
@end

@implementation InfoViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.title = @"Info";
    self.view.backgroundColor = [UIColor colorWithRed:0.05 green:0.05 blue:0.06 alpha:1.0];

    UILabel *initials = [[UILabel alloc] init];
    initials.text = kAuthorInitials;
    initials.font = [UIFont systemFontOfSize:64 weight:UIFontWeightBlack];
    initials.textColor = [UIColor colorWithRed:0.10 green:0.55 blue:0.30 alpha:1.0];
    initials.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:initials];

    UILabel *subtitle = [[UILabel alloc] init];
    subtitle.text = @"kernel external for iOS 15.0 – 17.3.1";
    subtitle.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    subtitle.textColor = [UIColor colorWithWhite:0.6 alpha:1.0];
    subtitle.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:subtitle];

    NSArray<NSArray<NSString *> *> *rows = @[
        @[@"TG Group", kTelegramGroup],
        @[@"TG Channel", kTelegramChannel],
        @[@"Contact", kContactTelegram],
        @[@"Version", kProjectVersion],
    ];

    CGFloat y = 210;
    for (NSArray *row in rows) {
        UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
        btn.frame = CGRectMake(20, y, self.view.bounds.size.width - 40, 52);
        btn.backgroundColor = [UIColor colorWithWhite:0.11 alpha:1.0];
        btn.layer.cornerRadius = 12;

        NSString *url = row[1];
        NSString *display = [url hasPrefix:@"http"] ? [url stringByReplacingOccurrencesOfString:@"https://" withString:@""] : url;
        NSMutableAttributedString *title = [[NSMutableAttributedString alloc] initWithString:[NSString stringWithFormat:@"%@  ", row[0]] attributes:@{NSForegroundColorAttributeName: [UIColor colorWithWhite:0.6 alpha:1.0], NSFontAttributeName: [UIFont systemFontOfSize:15 weight:UIFontWeightSemibold]}];
        [title appendAttributedString:[[NSAttributedString alloc] initWithString:display attributes:@{NSForegroundColorAttributeName: [UIColor colorWithRed:0.30 green:0.78 blue:0.47 alpha:1.0], NSFontAttributeName: [UIFont monospacedSystemFontOfSize:14 weight:UIFontWeightMedium]}]];
        [btn setAttributedTitle:title forState:UIControlStateNormal];
        [btn addTarget:self action:@selector(linkTapped:) forControlEvents:UIControlEventTouchUpInside];
        btn.accessibilityValue = url;
        btn.contentHorizontalAlignment = UIControlContentHorizontalAlignmentLeft;
        btn.titleEdgeInsets = UIEdgeInsetsMake(0, 16, 0, 8);
        [self.view addSubview:btn];
        y += 60;
    }

    UILabel *footer = [[UILabel alloc] init];
    footer.text = [NSString stringWithFormat:@"task_for_pid + kernel extmod hygiene\nbuilt on Dopamine 3.x exploit stack (kfd / ClearSword)"];
    footer.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    footer.textColor = [UIColor colorWithWhite:0.35 alpha:1.0];
    footer.textAlignment = NSTextAlignmentCenter;
    footer.numberOfLines = 0;
    footer.frame = CGRectMake(16, y + 24, self.view.bounds.size.width - 32, 60);
    [self.view addSubview:footer];

    // position author labels
    initials.frame = CGRectMake(0, 90, self.view.bounds.size.width, 80);
    subtitle.frame = CGRectMake(0, 172, self.view.bounds.size.width, 20);
}

- (void)linkTapped:(UIButton *)sender
{
    NSString *url = sender.accessibilityValue;
    if ([url hasPrefix:@"http"]) {
        NSURL *u = [NSURL URLWithString:url];
        if (u) [UIApplication.sharedApplication openURL:u options:@{} completionHandler:nil];
    }
}

@end
