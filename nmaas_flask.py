from flask import Flask


class NMaaS_Framework():

    app = Flask(__name__)
    def __init__(self):
        print("NMaaS REST API controller started")
        self.app.run()

        #reference to nmaas_network_controller object

        # print(self.nmaas.getPaths())

    @app.route("/")
    def index(self):
        retval = "\nHello, you're talking to the NMaaS controller!\n" \
                 "Current feautres could be accessed by REST API:\n" \
                 "For features go to /features:\n"

        return retval

    @app.route("/features")
    def features(self):
        retval ="\nThese are the avaiable features of NMaaS:\n" \
                " - hop-by-hop latency measurement:\n" \
                "\t -> for more info to to: /features/hop-by-hop-latency\n"
        return  retval


    @app.route("/features/hop-by-hop-latency")
    def hop_by_hop_latency(self):
        retval ="\nHop-by-hop latency measurement\n" \
                "Usage:\n" \
                "/features/hop-by-hop-latency/[from]/[to]\n" \
                "where [from] and [to] are host identifiers\n"
        return retval


if __name__ == "__main__":
    nmaas_controller = NMaaS_RESTAPI_Controller()
    nmaas_controller.app.run()