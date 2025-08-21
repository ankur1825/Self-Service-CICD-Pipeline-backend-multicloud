#!/usr/bin/env python3
import json, argparse, boto3, os

def main():
  ap = argparse.ArgumentParser()
  ap.add_argument("--wave", required=True, help="path to wave.json")
  args = ap.parse_args()

  wave = json.load(open(args.wave))
  params = wave["params"]
  region = params["region"]

  mgn = boto3.client("mgn", region_name=region)

  # Example: ensure a replication template exists (you’d parameterize more settings)
  tmpl = mgn.create_replication_configuration_template(
      stagingAreaSubnetId=params["private_subnet_ids"][0],
      useDedicatedReplicationServer=True,
      ebsEncryption="DEFAULT",
      replicationServersSecurityGroupsIDs=params["security_group_ids"],
      tags=params.get("tags", {})
  )
  print("[mgn] created/ensured replication template:", tmpl["arn"])

  # In reality you associate source servers by IDs (already discovered by the agent)
  # and start replication — this is environment-specific.
  print("[mgn] NOTE: install MGN agent on sources; associate to replication template; replication then starts.")
  return 0

if __name__ == "__main__":
  exit(main())
