import random
from paho.mqtt import client as mqtt_client


class PacketPublisher(mqtt_client.Client):

    def __init__(self, config: dict):
        broker = config.get("broker", None)
        port = config.get("port", None)
        self.topic = config.get("topic", None)
        super().__init__(client_id=f'python-mqtt-{random.randint(0, 1000)}')
        if self.topic is None:
            raise ValueError("topic is wrongly formatted! check \"topic\" "
                             "field in \"publish\" in config file.")

        def on_connect(client, userdata, flags, rc, *args, **kwargs):
            if rc == 0:
                print("Connected to MQTT Broker!")
            else:
                print("Failed to connect, return code %d\n", rc)
        self.on_connect = on_connect
        self.connect(broker, port)
        self.loop_start()

    def publish_packet(self, msg: str):
        self.publish(self.topic, msg)

