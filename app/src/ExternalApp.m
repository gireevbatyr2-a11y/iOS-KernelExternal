#import "ExternalApp.h"
#import "RunViewController.h"
#import "InfoViewController.h"

@implementation ExternalApp

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];

    RunViewController *run = [[RunViewController alloc] init];
    UINavigationController *runNav = [[UINavigationController alloc] initWithRootViewController:run];
    runNav.tabBarItem = [[UITabBarItem alloc] initWithTitle:@"Run" image:[UIImage systemImageNamed:@"play.circle.fill"] tag:0];

    InfoViewController *info = [[InfoViewController alloc] init];
    UINavigationController *infoNav = [[UINavigationController alloc] initWithRootViewController:info];
    infoNav.tabBarItem = [[UITabBarItem alloc] initWithTitle:@"Info" image:[UIImage systemImageNamed:@"person.crop.circle"] tag:1];

    UITabBarController *tabs = [[UITabBarController alloc] init];
    tabs.viewControllers = @[runNav, infoNav];
    tabs.tabBar.barStyle = UIBarStyleBlack;

    self.window.rootViewController = tabs;
    self.window.backgroundColor = [UIColor colorWithRed:0.05 green:0.05 blue:0.06 alpha:1.0];
    [self.window makeKeyAndVisible];
    return YES;
}

@end
