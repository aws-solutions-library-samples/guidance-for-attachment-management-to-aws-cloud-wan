import { Construct } from "constructs";
import {
    TerraformStack,
    TerraformHclModule,
    Token,
    Fn,
} from "cdktf";
import { AwsProvider } from "../.gen/providers/aws/provider";
import { SnsTopic } from "../.gen/providers/aws/sns-topic";
import { SnsTopicPolicy } from "../.gen/providers/aws/sns-topic-policy";
import { DataAwsIamPolicyDocument } from "../.gen/providers/aws/data-aws-iam-policy-document";
import { CloudwatchEventRule } from "../.gen/providers/aws/cloudwatch-event-rule";
import { CloudwatchEventTarget } from "../.gen/providers/aws/cloudwatch-event-target";
import { LambdaPermission } from "../.gen/providers/aws/lambda-permission";


export interface NetworkManagerEventsConfig {
    readonly managerName: string;  
    readonly awsAccountId: string;  
}


export class NetworkManagerEvents extends Construct {

    // Config Attributes
    id = "";
    parentStack = {} as TerraformStack;
    awsProvider = {} as AwsProvider;
    config = {} as NetworkManagerEventsConfig;

    snsTopic = {} as SnsTopic;

    constructor(scope: Construct, id: string, parentStack: TerraformStack,
        awsProvider: AwsProvider,
        config: NetworkManagerEventsConfig
    ) {
        super(scope, id);
        
        // Store references to the parant stack
        this.id = id;
        this.parentStack = parentStack;
        this.awsProvider = awsProvider;
        this.config = config;
        
        // Process Defaults

        
        // Create SNS Topic for event publishing
        this.snsTopic = new SnsTopic(this.parentStack, `${this.id}_sns`, {
            provider: this.awsProvider,
            name: this.config.managerName,
            fifoTopic: false,
            contentBasedDeduplication: false,
            kmsMasterKeyId: "alias/aws/sns",
        });

        let snsPolicy = new DataAwsIamPolicyDocument(this.parentStack, `${this.id}_sns_policy_doc`, {
            statement: [
                { 
                    sid: "AllowPublish",
                    effect: "Allow",
                    actions: [
                        "sns:Publish",
                        "sns:Subscribe"
                    ],
                    principals: [
                        {
                            type: "AWS",
                            identifiers: [ this.config.awsAccountId ]
                        },
                    ],
                    resources: [this.snsTopic.arn],
                },
            ],
        });
        new SnsTopicPolicy(this.parentStack, `${this.id}_sns_policy`, {
            provider: this.awsProvider,
            arn: this.snsTopic.arn,
            policy: Token.asString(snsPolicy.json),
        });

        

        // Create lambda using vanilla terraform module
        // https://developer.hashicorp.com/terraform/cdktf/concepts/modules
        const lambdaModule = new TerraformHclModule(this.parentStack, `${this.id}_module_crawler_lambda`, {
            source: "terraform-aws-modules/lambda/aws",
            providers: [this.awsProvider],
            variables: {
                function_name: this.config.managerName,
                handler: "lambda_handler.handler",
                runtime: "python3.9",
                source_path: "../lambda/sns_publish_attributes", // build dir: ./cdktf.out/stacks/StackName
                memory_size: 128,
                timeout: 120,
                attach_policy_json: "true",
                cloudwatch_logs_retention_in_days: 1,
                environment_variables: {
                    SNS_TOPIC_ARN: this.snsTopic.arn,
                },
                policy_json: Token.asString(
                    Fn.jsonencode({
                        Version: "2012-10-17",
                        Statement: [
                            {
                                Effect: "Allow",
                                Action: [
                                    "sns:Publish",
                                ],
                                Resource: [this.snsTopic.arn]
                            }
                        ]
                    })
                ) 
            },
        });
        

        // Configure the Event Bridge
        let eventRule = new CloudwatchEventRule(this.parentStack, `${this.id}_cwevent_rule`, {
            provider: this.awsProvider,
            eventBusName: "default",
            eventPattern: JSON.stringify( { source: ["aws.networkmanager"] } ),
            name: this.config.managerName,
        });

        // Allow lambda to read sqs
        new LambdaPermission(this.parentStack, `${this.id}_lambda_allow_sns`, {
            provider: this.awsProvider,
            statementId: "AllowExecutionFromEvents",
            action: "lambda:InvokeFunction",
            functionName: Token.asString(lambdaModule.get("lambda_function_name")),
            principal: "events.amazonaws.com",
            sourceArn: eventRule.arn,
        });

        new CloudwatchEventTarget(this.parentStack, `${this.id}_cwevent_target`, {
            provider: this.awsProvider,
            rule: eventRule.id,
            arn: Token.asString(lambdaModule.get("lambda_function_arn"))
        });        

    }
}